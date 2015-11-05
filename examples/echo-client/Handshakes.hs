{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings, RecordWildCards #-}

module Handshakes
  ( HandshakeKeys(..),
    HandshakeType(..),
    processHandshake
  ) where

import Control.Concurrent.Async (concurrently)
import Control.Concurrent.MVar  (MVar, newEmptyMVar)
import Control.Exception        (Exception, throw, throwIO)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Text                (Text)
import Data.Text.Encoding       (encodeUtf8, decodeUtf8)
import qualified Data.Text as T (concat)
import Data.Typeable            (Typeable)
import GHC.Generics
import Pipes
import Pipes.Aeson
import Pipes.Parse
import qualified Pipes.ByteString as P

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

instance ToJSON HandshakeType where
  toJSON (NoiseNN) = String . makeHSN $ "NN"
  toJSON (NoiseKN) = String . makeHSN $ "KN"
  toJSON (NoiseNK) = String . makeHSN $ "NK"
  toJSON (NoiseKK) = String . makeHSN $ "KK"
  toJSON (NoiseNE) = String . makeHSN $ "NE"
  toJSON (NoiseKE) = String . makeHSN $ "KE"
  toJSON (NoiseNX) = String . makeHSN $ "NX"
  toJSON (NoiseKX) = String . makeHSN $ "KX"
  toJSON (NoiseXN) = String . makeHSN $ "XN"
  toJSON (NoiseIN) = String . makeHSN $ "IN"
  toJSON (NoiseXK) = String . makeHSN $ "XK"
  toJSON (NoiseIK) = String . makeHSN $ "IK"
  toJSON (NoiseXE) = String . makeHSN $ "XE"
  toJSON (NoiseIE) = String . makeHSN $ "IE"
  toJSON (NoiseXX) = String . makeHSN $ "XX"
  toJSON (NoiseIX) = String . makeHSN $ "IX"

data InitialMessage =
  InitialMessage { handshakeType :: HandshakeType
                 } deriving (Generic)

instance ToJSON InitialMessage

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
                 -> (ClientSender, ClientReceiver)
                 -> HandshakeType
                 -> IO ()
processHandshake hks (cs, cr) ht = do
  csmv <- newEmptyMVar

  let im  = InitialMessage ht
      imo = case toJSON im of
        (Object o) -> o
        _          -> undefined

  runEffect $ encodeObject imo >-> cs

  runEffect $ cr >-> deserializeHM >-> mkHandshakePipe ht hks csmv >-> serializeHM >-> cs

  putStrLn "Handshake complete"

  void $ concurrently (runEffect (P.stdin >-> messageEncryptPipe csmv >-> serializeM >-> cs))
                      (runEffect (cr >-> deserializeM >-> messageDecryptPipe csmv >-> P.stdout))

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
    NoiseNN -> noiseNNIPipe noiseNNHS csmv
    NoiseKN -> noiseKNIPipe (noiseKNHS hks) csmv
    NoiseNK -> noiseNKIPipe (noiseNKHS hks) csmv
    NoiseKK -> noiseKKIPipe (noiseKKHS hks) csmv
    NoiseNE -> noiseNEIPipe (noiseNEHS hks) csmv
    NoiseKE -> noiseKEIPipe (noiseKEHS hks) csmv
    NoiseNX -> noiseNXIPipe (noiseNXHS hks) csmv
    NoiseKX -> noiseKXIPipe (noiseKXHS hks) csmv
    NoiseXN -> noiseXNIPipe (noiseXNHS hks) csmv
    NoiseIN -> noiseINIPipe (noiseINHS hks) csmv
    NoiseXK -> noiseXKIPipe (noiseXKHS hks) csmv
    NoiseIK -> noiseIKIPipe (noiseIKHS hks) csmv
    NoiseXE -> noiseXEIPipe (noiseXEHS hks) csmv
    NoiseIE -> noiseIEIPipe (noiseIEHS hks) csmv
    NoiseXX -> noiseXXIPipe (noiseXXHS hks) csmv
    NoiseIX -> noiseIXIPipe (noiseIXHS hks) csmv

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
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseKNI0)

noiseNKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NK")
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseNKI0)

noiseKKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKKI0)

noiseNEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NE")
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseNEI0)

noiseKEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseKEI0)

noiseNXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "NX")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "KX")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKXI0)

noiseXNHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseINHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseXKI0)

noiseIKHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseIKI0)

noiseXEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseXEI0)

noiseIEHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseIEI0)

noiseXXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "XX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXHS HandshakeKeys{..} =
  handshakeState
  (makeHSN' "IX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing
