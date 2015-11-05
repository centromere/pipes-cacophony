{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings, RecordWildCards #-}

module Handshakes
  ( HandshakeKeys(..),
    processHandshake
  ) where

import Control.Concurrent.MVar  (MVar, newEmptyMVar)
import Control.Exception        (Exception, throw, throwIO)
import Control.Monad            (unless, forever)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Maybe               (isNothing, fromJust)
import Data.Text                (Text)
import Data.Text.Encoding       (encodeUtf8, decodeUtf8)
import qualified Data.Text as T (concat)
import Data.Typeable            (Typeable)
import GHC.Generics
import Pipes
import Pipes.Aeson
import Pipes.Parse

import Crypto.Noise.Descriptors
import Crypto.Noise.Handshake
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

import Pipes.Noise

data HandshakeKeys =
  HandshakeKeys { initStatic    :: KeyPair Curve25519
                , respStatic    :: KeyPair Curve25519
                , respEphemeral :: KeyPair Curve25519
                }

data HandshakeException = HandshakeFailed
                        | InvalidHandshakeType Text
                        | Base64DecodingFailure String
  deriving (Show, Typeable)

instance Exception HandshakeException

data HandshakeType = NoiseNN
                   | NoiseKN
                   | NoiseNK
                   | NoiseKK
                   | NoiseNE
                   | NoiseKE
                   | NoiseNX
                   | NoiseKX
                   | NoiseXN
                   | NoiseIN
                   | NoiseXK
                   | NoiseIK
                   | NoiseXE
                   | NoiseIE
                   | NoiseXX
                   | NoiseIX

instance FromJSON HandshakeType where
  parseJSON (String ht)
    | ht == makeHSN "NN" = pure NoiseNN
    | ht == makeHSN "KN" = pure NoiseKN
    | ht == makeHSN "NK" = pure NoiseNK
    | ht == makeHSN "KK" = pure NoiseKK
    | ht == makeHSN "NE" = pure NoiseNE
    | ht == makeHSN "KE" = pure NoiseKE
    | ht == makeHSN "NX" = pure NoiseNX
    | ht == makeHSN "KX" = pure NoiseKX
    | ht == makeHSN "XN" = pure NoiseXN
    | ht == makeHSN "IN" = pure NoiseIN
    | ht == makeHSN "XK" = pure NoiseXK
    | ht == makeHSN "IK" = pure NoiseIK
    | ht == makeHSN "XE" = pure NoiseXE
    | ht == makeHSN "IE" = pure NoiseIE
    | ht == makeHSN "XX" = pure NoiseXX
    | ht == makeHSN "IX" = pure NoiseIX
    | otherwise          = throw $ InvalidHandshakeType ht
  parseJSON _            = mzero

data InitialMessage =
  InitialMessage { handshakeType :: HandshakeType
                 } deriving (Generic)

instance FromJSON InitialMessage

newtype HandshakeMessage = HandshakeMessage ByteString

instance FromJSON HandshakeMessage where
  parseJSON = withObject "handshake data" $
    \o -> pure
          . either
          (throw . Base64DecodingFailure)
          HandshakeMessage
          . B64.decode
          . encodeUtf8
          =<< (o .: "handshakeData")

instance ToJSON HandshakeMessage where
  toJSON (HandshakeMessage hm) =
    object [ "handshakeData" .= encodedData ]
    where
      encodedData = decodeUtf8 . B64.encode $ hm

newtype Message = Message ByteString

instance FromJSON Message where
  parseJSON = withObject "message" $
    \o -> pure
          . either
          (throw . Base64DecodingFailure)
          Message
          . B64.decode
          . encodeUtf8
          =<< (o .: "message")

instance ToJSON Message where
  toJSON (Message m) =
    object [ "message" .= encodedData ]
    where
      encodedData = decodeUtf8 . B64.encode $ m

type ClientReceiver  = Producer' ByteString IO ()
type ClientSender    = Consumer' ByteString IO ()

makeHSN :: Text -> Text
makeHSN ht = T.concat ["Noise_", ht, "_25519_ChaChaPoly1305_SHA256"]

makeHSN' :: ByteString -> ScrubbedBytes
makeHSN' ht = concatSB [prefix, convert ht, suffix]
  where
    prefix = bsToSB' "Noise_"
    suffix = bsToSB' "_25519_ChaChaPoly1305_SHA256"

processHandshake :: HandshakeKeys
                 -> (ClientReceiver, ClientSender)
                 -> IO ()
processHandshake hks (cr, cs) = do
  csmv <- newEmptyMVar

  mer <- evalStateT decode cr
  unless (isNothing mer) $
    case fromJust mer of
      Left e -> throwIO e
      Right (InitialMessage r) ->
        runHandshake $ mkHandshakePipe r hks csmv

  forever . runEffect $
    cr >-> deserializeM >-> messageDecryptPipe csmv >-> messageEncryptPipe csmv >-> serializeM >-> cs
  where
    runHandshake hp = runEffect $ cr >-> deserializeHM >-> hp >-> serializeHM >-> cs

deserializeHM :: Pipe ByteString ByteString IO ()
deserializeHM = parseForever_ decode >-> grabResult
  where
    grabResult = do
      mer <- await
      case mer of
        Left e -> lift $ throwIO e
        Right (HandshakeMessage r) -> yield r
      grabResult

serializeHM :: Pipe ByteString ByteString IO ()
serializeHM = encodeResult >-> for cat encodeObject
  where
    encodeResult = do
      hm <- await
      case toJSON . HandshakeMessage $ hm of
        (Object o) -> yield o
        _          -> undefined
      encodeResult

deserializeM :: Pipe ByteString ByteString IO ()
deserializeM = parseForever_ decode >-> grabResult
  where
    grabResult = do
      mer <- await
      case mer of
        Left e -> lift $ throwIO e
        Right (Message r) -> yield r
      grabResult

serializeM :: Pipe ByteString ByteString IO ()
serializeM = encodeResult >-> for cat encodeObject
  where
    encodeResult = do
      m <- await
      case toJSON . Message $ m of
        (Object o) -> yield o
        _          -> undefined
      encodeResult

mkHandshakePipe :: HandshakeType
                -> HandshakeKeys
                -> MVar (CipherStatePair ChaChaPoly1305)
                -> HandshakePipe IO ()
mkHandshakePipe ht hks csmv =
  case ht of
    NoiseNN -> noiseNNRPipe noiseNNHS csmv
    NoiseKN -> noiseKNRPipe (noiseKNHS hks) csmv
    NoiseNK -> noiseNKRPipe (noiseNKHS hks) csmv
    NoiseKK -> noiseKKRPipe (noiseKKHS hks) csmv
    NoiseNE -> noiseNERPipe (noiseNEHS hks) csmv
    NoiseKE -> noiseKERPipe (noiseKEHS hks) csmv
    NoiseNX -> noiseNXRPipe (noiseNXHS hks) csmv
    NoiseKX -> noiseKXRPipe (noiseKXHS hks) csmv
    NoiseXN -> noiseXNRPipe (noiseXNHS hks) csmv
    NoiseIN -> noiseINRPipe (noiseINHS hks) csmv
    NoiseXK -> noiseXKRPipe (noiseXKHS hks) csmv
    NoiseIK -> noiseIKRPipe (noiseIKHS hks) csmv
    NoiseXE -> noiseXERPipe (noiseXEHS hks) csmv
    NoiseIE -> noiseIERPipe (noiseIEHS hks) csmv
    NoiseXX -> noiseXXRPipe (noiseXXHS hks) csmv
    NoiseIX -> noiseIXRPipe (noiseIXHS hks) csmv

noiseNNHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNHS =
  handshakeState
  (makeHSN' "NN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KN")
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKNR0)

noiseNKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseNKR0)

noiseKKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KK")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKKR0)

noiseNEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseNER0)

noiseKEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KE")
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing
  (Just noiseKER0)

noiseNXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KX")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKXR0)

noiseXNHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseINHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseXKR0)

noiseIKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseIKR0)

noiseXEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseXER0)

noiseIEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseIER0)

noiseXXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing
