{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings, RecordWildCards #-}

module Handshakes
  ( HandshakeKeys(..),
    HandshakeType(..),
    processHandshake
  ) where

import Control.Concurrent.Async (race_)
import Control.Concurrent.MVar  (newEmptyMVar, putMVar)
import Control.Exception        (Exception, throw, throwIO)
import Control.Monad            (forever)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import Data.ByteString          (ByteString)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Maybe               (fromJust)
import Data.Text                (Text)
import Data.Text.Encoding       (encodeUtf8, decodeUtf8)
import qualified Data.Text as T (concat)
import Data.Typeable            (Typeable)
import GHC.Generics
import Pipes
import Pipes.Aeson              (DecodingError)
import Pipes.Aeson.Unchecked
import Pipes.Network.TCP
import Pipes.Parse
import qualified Pipes.ByteString as P

import Crypto.Noise.Handshake
import Crypto.Noise.HandshakePatterns
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types       (Plaintext(..))

import Pipes.Noise

data HandshakeKeys =
  HandshakeKeys { psk           :: Maybe Plaintext
                , initStatic    :: KeyPair Curve25519
                , respStatic    :: PublicKey Curve25519
                , respEphemeral :: PublicKey Curve25519
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
                   | NoiseXR

instance ToJSON HandshakeType where
  toJSON NoiseNN = String . makeHSN $ "NN"
  toJSON NoiseKN = String . makeHSN $ "KN"
  toJSON NoiseNK = String . makeHSN $ "NK"
  toJSON NoiseKK = String . makeHSN $ "KK"
  toJSON NoiseNE = String . makeHSN $ "NE"
  toJSON NoiseKE = String . makeHSN $ "KE"
  toJSON NoiseNX = String . makeHSN $ "NX"
  toJSON NoiseKX = String . makeHSN $ "KX"
  toJSON NoiseXN = String . makeHSN $ "XN"
  toJSON NoiseIN = String . makeHSN $ "IN"
  toJSON NoiseXK = String . makeHSN $ "XK"
  toJSON NoiseIK = String . makeHSN $ "IK"
  toJSON NoiseXE = String . makeHSN $ "XE"
  toJSON NoiseIE = String . makeHSN $ "IE"
  toJSON NoiseXX = String . makeHSN $ "XX"
  toJSON NoiseIX = String . makeHSN $ "IX"
  toJSON NoiseXR = String . makeHSN $ "XR"

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
makeHSN ht = T.concat ["Noise_", ht, "_25519_ChaChaPoly_SHA256"]

writeSocket :: ClientSender
            -> ByteString
            -> IO ()
writeSocket cs msg = runEffect $ (encode . HandshakeMessage) msg >-> cs

readSocket :: ClientReceiver
           -> IO ByteString
readSocket cr = do
  mer <- evalStateT decode cr
  case fromJust mer of
    Left e -> throwIO e
    Right (HandshakeMessage r) -> return r

processHandshake :: HandshakeKeys
                 -> Socket
                 -> HandshakeType
                 -> IO ()
processHandshake hks s ht = do
  let clientSender = toSocket s
      clientReceiver = fromSocketTimeout 120000000 s 4096

  scsmv <- newEmptyMVar
  rcsmv <- newEmptyMVar

  runEffect $ (encode . InitialMessage) ht >-> clientSender

  let hc = HandshakeCallbacks (writeSocket clientSender)
                              (readSocket clientReceiver)
                              (\_ -> return ())
                              (return "")
  (scs, rcs) <- runHandshake (mkHandshakePipe ht hks) hc
  putMVar scsmv scs
  putMVar rcsmv rcs

  putStrLn "Handshake complete"

  race_ (runEffect (P.stdin                  >->
                    messageEncryptPipe scsmv >->
                    serializeM               >->
                    clientSender))
        (runEffect ((() <$ parsed_ decode clientReceiver) >->
                    deserializeM                          >->
                    messageDecryptPipe rcsmv              >->
                    P.stdout))

deserializeM :: Pipe (Either DecodingError Message) ByteString IO r
deserializeM = forever $ do
  mer <- await
  case mer of
    Left e -> lift $ throwIO e
    Right (Message r) -> yield r

serializeM :: Pipe ByteString ByteString IO ()
serializeM = encodeResult >-> for cat encode
  where
    encodeResult = forever $ do
      m <- Message <$> await
      yield m

mkHandshakePipe :: HandshakeType
                -> HandshakeKeys
                -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
mkHandshakePipe ht hks =
  case ht of
    NoiseNN -> noiseNNIHS hks
    NoiseKN -> noiseKNIHS hks
    NoiseNK -> noiseNKIHS hks
    NoiseKK -> noiseKKIHS hks
    NoiseNE -> noiseNEIHS hks
    NoiseKE -> noiseKEIHS hks
    NoiseNX -> noiseNXIHS hks
    NoiseKX -> noiseKXIHS hks
    NoiseXN -> noiseXNIHS hks
    NoiseIN -> noiseINIHS hks
    NoiseXK -> noiseXKIHS hks
    NoiseIK -> noiseIKIHS hks
    NoiseXE -> noiseXEIHS hks
    NoiseIE -> noiseIEIHS hks
    NoiseXX -> noiseXXIHS hks
    NoiseIX -> noiseIXIHS hks
    NoiseXR -> noiseXRIHS hks

noiseNNIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  True

noiseKNIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseNKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNK
  ""
  psk
  Nothing
  Nothing
  (Just respStatic)
  Nothing
  True

noiseKKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  Nothing
  True

noiseNEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNE
  ""
  psk
  Nothing
  Nothing
  (Just respStatic)
  (Just respEphemeral)
  True

noiseKEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  (Just respEphemeral)
  True

noiseNXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNX
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  True

noiseKXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKX
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  Nothing
  True

noiseXNIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseINIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIN
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseXKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  Nothing
  True

noiseIKIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIK
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  Nothing
  True

noiseXEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  (Just respEphemeral)
  True

noiseIEIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIE
  ""
  psk
  (Just initStatic)
  Nothing
  (Just respStatic)
  (Just respEphemeral)
  True

noiseXXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXX
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseIXIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXIHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIX
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True

noiseXRIHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXRIHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
  noiseXR
  ""
  psk
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  True
