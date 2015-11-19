{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings, RecordWildCards #-}

module Handshakes
  ( HandshakeKeys(..),
    processHandshake
  ) where

import Control.Concurrent.MVar  (MVar, newEmptyMVar)
import Control.Exception        (Exception, throw, throwIO)
import Control.Monad            (unless)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import Data.ByteString          (ByteString)
import Data.ByteString.Char8    (pack)
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

import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash.SHA256

import Pipes.Noise

data HandshakeKeys =
  HandshakeKeys { initStatic    :: PublicKey Curve25519
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
                   deriving (Show)

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
makeHSN ht = T.concat ["Noise_", ht, "_25519_ChaChaPoly_SHA256"]

processHandshake :: HandshakeKeys
                 -> (ClientReceiver, ClientSender)
                 -> (ByteString -> IO ())
                 -> IO ()
processHandshake hks (cr, cs) logger = do
  csmv <- newEmptyMVar

  mer <- evalStateT decode cr
  unless (isNothing mer) $
    case fromJust mer of
      Left e -> throwIO e
      Right (InitialMessage r) -> do
        logger $ "requested handshake: " `mappend` (pack . show) r
        runHandshake $ mkHandshakePipe r hks csmv
        logger "handshake complete"

  runEffect $
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
    NoiseNN -> noiseNNRPipe noiseNNRHS csmv
    NoiseKN -> noiseKNRPipe (noiseKNRHS hks) csmv
    NoiseNK -> noiseNKRPipe (noiseNKRHS hks) csmv
    NoiseKK -> noiseKKRPipe (noiseKKRHS hks) csmv
    NoiseNE -> noiseNERPipe (noiseNERHS hks) csmv
    NoiseKE -> noiseKERPipe (noiseKERHS hks) csmv
    NoiseNX -> noiseNXRPipe (noiseNXRHS hks) csmv
    NoiseKX -> noiseKXRPipe (noiseKXRHS hks) csmv
    NoiseXN -> noiseXNRPipe (noiseXNRHS hks) csmv
    NoiseIN -> noiseINRPipe (noiseINRHS hks) csmv
    NoiseXK -> noiseXKRPipe (noiseXKRHS hks) csmv
    NoiseIK -> noiseIKRPipe (noiseIKRHS hks) csmv
    NoiseXE -> noiseXERPipe (noiseXERHS hks) csmv
    NoiseIE -> noiseIERPipe (noiseIERHS hks) csmv
    NoiseXX -> noiseXXRPipe (noiseXXRHS hks) csmv
    NoiseIX -> noiseIXRPipe (noiseIXRHS hks) csmv

noiseNNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNRHS =
  handshakeState
  noiseNNR
  ""
  (Just "cacophony")
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNRHS HandshakeKeys{..} =
  handshakeState
  noiseKNR
  ""
  (Just "cacophony")
  Nothing
  Nothing
  (Just initStatic)
  Nothing

noiseNKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKRHS HandshakeKeys{..} =
  handshakeState
  noiseNKR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKRHS HandshakeKeys{..} =
  handshakeState
  noiseKKR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  (Just initStatic)
  Nothing

noiseNERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNERHS HandshakeKeys{..} =
  handshakeState
  noiseNER
  ""
  (Just "cacophony")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseKERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKERHS HandshakeKeys{..} =
  handshakeState
  noiseKER
  ""
  (Just "cacophony")
  (Just respStatic)
  (Just respEphemeral)
  (Just initStatic)
  Nothing

noiseNXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXRHS HandshakeKeys{..} =
  handshakeState
  noiseNXR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseKXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXRHS HandshakeKeys{..} =
  handshakeState
  noiseKXR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  (Just initStatic)
  Nothing

noiseXNRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNRHS HandshakeKeys{..} =
  handshakeState
  noiseXNR
  ""
  (Just "cacophony")
  Nothing
  Nothing
  Nothing
  Nothing

noiseINRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINRHS HandshakeKeys{..} =
  handshakeState
  noiseINR
  ""
  (Just "cacophony")
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKRHS HandshakeKeys{..} =
  handshakeState
  noiseXKR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKRHS HandshakeKeys{..} =
  handshakeState
  noiseIKR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseXERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXERHS HandshakeKeys{..} =
  handshakeState
  noiseXER
  ""
  (Just "cacophony")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseIERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIERHS HandshakeKeys{..} =
  handshakeState
  noiseIER
  ""
  (Just "cacophony")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing

noiseXXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXRHS HandshakeKeys{..} =
  handshakeState
  noiseXXR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing

noiseIXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXRHS HandshakeKeys{..} =
  handshakeState
  noiseIXR
  ""
  (Just "cacophony")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
