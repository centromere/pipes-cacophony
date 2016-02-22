{-# LANGUAGE DeriveGeneric, RankNTypes, ImpredicativeTypes,
    OverloadedStrings, RecordWildCards #-}

module Handshakes
  ( HandshakeKeys(..),
    processHandshake
  ) where

import Control.Concurrent.MVar  (newEmptyMVar, putMVar)
import Control.Exception        (Exception, throw, throwIO)
import Control.Monad            (forever,unless)
import Data.Aeson               (ToJSON, FromJSON, parseJSON, (.:),
                                 Value(..), (.=), toJSON, object, withObject)
import Data.ByteString          (ByteString)
import Data.ByteString.Char8    (pack)
import qualified Data.ByteString.Base64 as B64 (encode, decode)
import Data.Maybe               (isNothing, fromJust)
import Data.Monoid              ((<>))
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
                , initStatic    :: PublicKey Curve25519
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
                   | NoiseXR
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
    | ht == makeHSN "XR" = pure NoiseXR
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
                 -> (ByteString -> IO ())
                 -> IO ()
processHandshake hks s logger = do
  let clientReceiver = fromSocketTimeout 120000000 s 4096
      clientSender   = toSocket s

  scsmv <- newEmptyMVar
  rcsmv <- newEmptyMVar

  mer <- evalStateT decode clientReceiver
  unless (isNothing mer) $
    case fromJust mer of
      Left e -> throwIO e
      Right (InitialMessage r) -> do
        logger $ "requested handshake: " <> (pack . show) r
        let hc = HandshakeCallbacks (writeSocket clientSender)
                                    (readSocket clientReceiver)
                                    (\_ -> return ())
                                    (return "")
        (scs, rcs) <- runHandshake (mkHandshakeState r hks) hc
        putMVar scsmv scs
        putMVar rcsmv rcs
        logger "handshake complete"

  runEffect $ (() <$ parsed_ decode clientReceiver) >->
              deserializeM                          >->
              messageDecryptPipe rcsmv              >->
              messageEncryptPipe scsmv              >->
              serializeM                            >->
              clientSender

deserializeM :: Pipe (Either DecodingError Message) ByteString IO ()
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

mkHandshakeState :: HandshakeType
                 -> HandshakeKeys
                 -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
mkHandshakeState ht hks =
  case ht of
    NoiseNN -> noiseNNRHS hks
    NoiseKN -> noiseKNRHS hks
    NoiseNK -> noiseNKRHS hks
    NoiseKK -> noiseKKRHS hks
    NoiseNE -> noiseNERHS hks
    NoiseKE -> noiseKERHS hks
    NoiseNX -> noiseNXRHS hks
    NoiseKX -> noiseKXRHS hks
    NoiseXN -> noiseXNRHS hks
    NoiseIN -> noiseINRHS hks
    NoiseXK -> noiseXKRHS hks
    NoiseIK -> noiseIKRHS hks
    NoiseXE -> noiseXERHS hks
    NoiseIE -> noiseIERHS hks
    NoiseXX -> noiseXXRHS hks
    NoiseIX -> noiseIXRHS hks
    NoiseXR -> noiseXRRHS hks

noiseNNRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseKNRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKN
  ""
  psk
  Nothing
  Nothing
  (Just initStatic)
  Nothing
  False

noiseNKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseKKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKK
  ""
  psk
  (Just respStatic)
  Nothing
  (Just initStatic)
  Nothing
  False

noiseNERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNERHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseKERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKERHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  (Just initStatic)
  Nothing
  False

noiseNXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseNX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseKXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseKX
  ""
  psk
  (Just respStatic)
  Nothing
  (Just initStatic)
  Nothing
  False

noiseXNRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseINRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIN
  ""
  psk
  Nothing
  Nothing
  Nothing
  Nothing
  False

noiseXKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseIKRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIK
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseXERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXERHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseIERHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIERHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIE
  ""
  psk
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  False

noiseXXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseXX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseIXRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXRHS HandshakeKeys{..} =
  handshakeState $ HandshakeStateParams
  noiseIX
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False

noiseXRRHS :: HandshakeKeys
           -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXRRHS HandshakeKeys{..} = handshakeState $ HandshakeStateParams
  noiseXR
  ""
  psk
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  False
