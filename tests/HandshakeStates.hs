{-# LANGUAGE OverloadedStrings, RecordWildCards #-}
module HandshakeStates where

import Data.ByteString (ByteString)
import Data.Proxy

import Crypto.Noise.Descriptors
import Crypto.Noise.Handshake
import Crypto.Noise.Cipher
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Hash
import Crypto.Noise.Hash.SHA256
import Crypto.Noise.Types

data HandshakeKeys =
  HandshakeKeys { initStatic    :: KeyPair Curve25519
                , respStatic    :: KeyPair Curve25519
                , respEphemeral :: KeyPair Curve25519
                }

makeHSN :: ByteString -> ScrubbedBytes
makeHSN hs = concatSB [p, convert hs, u, a, u, b, u, c]
  where
    a = curveName  (Proxy :: Proxy Curve25519)
    b = cipherName (Proxy :: Proxy ChaChaPoly1305)
    c = hashName   (Proxy :: Proxy SHA256)
    u = bsToSB' "_"
    p = bsToSB' "Noise_"

noiseNNIHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNIHS =
  handshakeState
  (makeHSN "NN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseKNI0)

noiseNKIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NK")
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseNKI0)

noiseKKIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKKI0)

noiseNEIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNEIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NE")
  Nothing
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseNEI0)

noiseKEIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKEIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseKEI0)

noiseNXIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NX")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KX")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKXI0)

noiseXNIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseINIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IN")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseXKI0)

noiseIKIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IK")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseIKI0)

noiseXEIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXEIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseXEI0)

noiseIEIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIEIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IE")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  (Just (snd respEphemeral))
  (Just noiseIEI0)

noiseXXIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IX")
  (Just initStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseNIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "N")
  Nothing
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseNI0)

noiseKIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "K")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseKI0)

noiseXIHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXIHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "X")
  (Just initStatic)
  Nothing
  (Just (snd respStatic))
  Nothing
  (Just noiseXI0)

noiseNNRHS :: HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNNRHS =
  handshakeState
  (makeHSN "NN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseKNRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKNRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KN")
  Nothing
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKNR0)

noiseNKRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNKRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseNKR0)

noiseKKRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKKRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KK")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKKR0)

noiseNERHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNERHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseNER0)

noiseKERHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKERHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KE")
  (Just respStatic)
  (Just respEphemeral)
  (Just (snd initStatic))
  Nothing
  (Just noiseKER0)

noiseNXRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNXRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "NX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseKXRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKXRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "KX")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKXR0)

noiseXNRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXNRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseINRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseINRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IN")
  Nothing
  Nothing
  Nothing
  Nothing
  Nothing

noiseXKRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXKRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseXKR0)

noiseIKRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIKRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IK")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseIKR0)

noiseXERHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXERHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseXER0)

noiseIERHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIERHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IE")
  (Just respStatic)
  (Just respEphemeral)
  Nothing
  Nothing
  (Just noiseIER0)

noiseXXRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXXRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "XX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseIXRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseIXRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "IX")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseNRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseNRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "N")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  Nothing

noiseKRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseKRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "K")
  (Just respStatic)
  Nothing
  (Just (snd initStatic))
  Nothing
  (Just noiseKR0)

noiseXRHS :: HandshakeKeys
          -> HandshakeState ChaChaPoly1305 Curve25519 SHA256
noiseXRHS HandshakeKeys{..} =
  handshakeState
  (makeHSN "X")
  (Just respStatic)
  Nothing
  Nothing
  Nothing
  (Just noiseXR0)


