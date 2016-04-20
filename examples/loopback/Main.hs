module Main where

import Control.Lens
import Control.Monad (forever)
import Data.ByteString.Char8 (unpack, pack)
import Pipes
import qualified Pipes.Prelude as P

import Crypto.Noise
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.HandshakePatterns (noiseNN)
import Crypto.Noise.Hash.SHA256
import Data.ByteArray.Extend

import Pipes.Noise

strToSB :: Pipe String ScrubbedBytes IO (Either NoiseException ())
strToSB = forever $ await >>= yield . convert . pack

sbToStr :: Pipe ScrubbedBytes String IO (Either NoiseException ())
sbToStr = forever $ await >>= yield . unpack . convert

main :: IO ()
main = do
  iek <- dhGenKey :: IO (KeyPair Curve25519)
  rek <- dhGenKey :: IO (KeyPair Curve25519)

  let idho     = defaultHandshakeOpts noiseNN InitiatorRole
      rdho     = defaultHandshakeOpts noiseNN ResponderRole
      iho      = idho & hoLocalEphemeral .~ Just iek
      rho      = rdho & hoLocalEphemeral .~ Just rek
      ins      = noiseState iho :: NoiseState ChaChaPoly1305 Curve25519 SHA256
      rns      = noiseState rho :: NoiseState ChaChaPoly1305 Curve25519 SHA256

  (iip, iop) <- mkNoisePipes ins
  (rip, rop) <- mkNoisePipes rns

  result <- runEffect $ (Right () <$ P.stdinLn) >-> strToSB >-> iop >-> rip >-> rop >-> iip >-> sbToStr >-> (Right () <$ P.stdoutLn)
  case result of
    Left e  -> print e
    Right _ -> return ()
