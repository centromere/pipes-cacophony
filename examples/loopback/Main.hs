module Main where

import Control.Monad         (forever)
import Data.ByteString.Char8 (unpack, pack)
import Data.Maybe            (fromMaybe)
import Pipes
import qualified Pipes.Prelude as P

import Crypto.Noise
import Crypto.Noise.Cipher.ChaChaPoly1305
import Crypto.Noise.DH
import Crypto.Noise.DH.Curve25519
import Crypto.Noise.HandshakePatterns (noiseNN)
import Crypto.Noise.Hash.SHA256

import Pipes.Noise

strToSB :: (Cipher c, DH d, Hash h)
        => Pipe String ScrubbedBytes IO (NoiseResult c d h)
strToSB = forever $ await >>= yield . convert . pack

sbToStr :: (Cipher c, DH d, Hash h)
        => Pipe ScrubbedBytes String IO (NoiseResult c d h)
sbToStr = forever $ await >>= yield . unpack . convert

performHandshake :: (Cipher c, DH d, Hash h)
                 => NoiseState c d h
                 -> NoiseState c d h
                 -> (NoiseState c d h, NoiseState c d h)
performHandshake ins rns = (ins'', rns'')
  where
    (NoiseResultMessage ct  ins')  = writeMessage mempty ins
    (NoiseResultMessage _   rns')  = readMessage ct rns
    (NoiseResultMessage ct' rns'') = writeMessage mempty rns'
    (NoiseResultMessage _   ins'') = readMessage ct' ins'

main :: IO ()
main = do
  iek <- dhGenKey :: IO (KeyPair Curve25519)
  rek <- dhGenKey :: IO (KeyPair Curve25519)

  let idho = defaultHandshakeOpts InitiatorRole "cacophony"
      rdho = defaultHandshakeOpts ResponderRole "cacophony"
      iho  = setLocalEphemeral (Just iek) idho
      rho  = setLocalEphemeral (Just rek) rdho
      ins  = noiseState iho noiseNN :: NoiseState ChaChaPoly1305 Curve25519 SHA256
      rns  = noiseState rho noiseNN :: NoiseState ChaChaPoly1305 Curve25519 SHA256

      (ins', rns') = performHandshake ins rns
      (iip, iop)   = fromMaybe (error "unable to make Noise pipe") $ mkNoisePipes ins'
      (rip, rop)   = fromMaybe (error "unable to make Noise pipe") $ mkNoisePipes rns'

  result <- runEffect $ (undefined <$ P.stdinLn)
                        >-> strToSB
                        >-> iop
                        >-> rip
                        >-> rop
                        >-> iip
                        >-> sbToStr
                        >-> (undefined <$ P.stdoutLn)
  case result of
    NoiseResultException ex -> print ex
    _ -> return ()
