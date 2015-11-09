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

import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash.SHA256

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
    NoiseNN -> noiseNNIPipe noiseNNIHS csmv
    NoiseKN -> noiseKNIPipe (noiseKNIHS hks) csmv
    NoiseNK -> noiseNKIPipe (noiseNKIHS hks) csmv
    NoiseKK -> noiseKKIPipe (noiseKKIHS hks) csmv
    NoiseNE -> noiseNEIPipe (noiseNEIHS hks) csmv
    NoiseKE -> noiseKEIPipe (noiseKEIHS hks) csmv
    NoiseNX -> noiseNXIPipe (noiseNXIHS hks) csmv
    NoiseKX -> noiseKXIPipe (noiseKXIHS hks) csmv
    NoiseXN -> noiseXNIPipe (noiseXNIHS hks) csmv
    NoiseIN -> noiseINIPipe (noiseINIHS hks) csmv
    NoiseXK -> noiseXKIPipe (noiseXKIHS hks) csmv
    NoiseIK -> noiseIKIPipe (noiseIKIHS hks) csmv
    NoiseXE -> noiseXEIPipe (noiseXEIHS hks) csmv
    NoiseIE -> noiseIEIPipe (noiseIEIHS hks) csmv
    NoiseXX -> noiseXXIPipe (noiseXXIHS hks) csmv
    NoiseIX -> noiseIXIPipe (noiseIXIHS hks) csmv

noiseNNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNIHS =
  handshakeState
  "NN"
  noiseNNI
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNIHS HandshakeKeys{..} =
  handshakeState
  "KN"
  noiseKNI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseNKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKIHS HandshakeKeys{..} =
  handshakeState
  "NK"
  noiseNKI
  ""
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing

noiseKKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKIHS HandshakeKeys{..} =
  handshakeState
  "KK"
  noiseKKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseNEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEIHS HandshakeKeys{..} =
  handshakeState
  "NE"
  noiseNEI
  ""
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseKEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEIHS HandshakeKeys{..} =
  handshakeState
  "KE"
  noiseKEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseNXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXIHS HandshakeKeys{..} =
  handshakeState
  "NX"
  noiseNXI
  ""
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXIHS HandshakeKeys{..} =
  handshakeState
  "KX"
  noiseKXI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXNIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNIHS HandshakeKeys{..} =
  handshakeState
  "XN"
  noiseXNI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseINIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINIHS HandshakeKeys{..} =
  handshakeState
  "IN"
  noiseINI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseXKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKIHS HandshakeKeys{..} =
  handshakeState
  "XK"
  noiseXKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseIKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKIHS HandshakeKeys{..} =
  handshakeState
  "IK"
  noiseIKI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing

noiseXEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEIHS HandshakeKeys{..} =
  handshakeState
  "XE"
  noiseXEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseIEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEIHS HandshakeKeys{..} =
  handshakeState
  "IE"
  noiseIEI
  ""
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))

noiseXXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXIHS HandshakeKeys{..} =
  handshakeState
  "XX"
  noiseXXI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing

noiseIXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXIHS HandshakeKeys{..} =
  handshakeState
  "IX"
  noiseIXI
  ""
  (Just initStatic)
  Nothing
  Nothing
  Nothing
