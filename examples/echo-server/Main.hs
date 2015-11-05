{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.AutoUpdate       (mkAutoUpdate, defaultUpdateSettings, updateAction)
import Control.Exception        (SomeException, displayException, handle)
import Data.Aeson               (encode, object, (.=))
import Data.ByteString          (ByteString, readFile, writeFile)
import Data.ByteString.Char8    (unpack)
import Data.ByteString.Lazy.Char8 (append)
import Data.Traversable         (forM)
import Data.UnixTime            (formatUnixTime, fromEpochTime)
import Pipes.Network.TCP
import Prelude                  hiding (readFile, writeFile)
import System.Directory         (doesFileExist)
import System.Environment       (getArgs)
import System.Log.FastLogger    (toLogStr, pushLogStr, LoggerSet, newFileLoggerSet)
import System.Posix             (epochTime)
import System.Posix.Files       (setFileCreationMask)

import Crypto.Noise.Curve
import Crypto.Noise.Curve.Curve25519
import Crypto.Noise.Types       (bsToSB', sbToBS')

import Handshakes

readKey :: FilePath -> IO (KeyPair Curve25519)
readKey f = fmap (curveBytesToPair . bsToSB') (readFile f)

genAndWriteKey :: FilePath -> IO (KeyPair Curve25519)
genAndWriteKey f = do
  pair@(sec, pub) <- curveGenKey
  writeFile f $ (sbToBS' . curveSecToBytes) sec
  writeFile (f `mappend` ".pub") $ (sbToBS' . curvePubToBytes) pub
  return pair

processKey :: FilePath -> IO (KeyPair Curve25519)
processKey f = do
  exists <- doesFileExist f
  if exists then
    readKey f
  else
    genAndWriteKey f

main :: IO ()
main = do
  [port] <- getArgs
  [is, rs, re] <- forM ["init_static", "resp_static", "resp_ephemeral"] processKey

  logHandle <- openLog "debug.log"
  au <- mkAutoUpdate defaultUpdateSettings { updateAction = getDateTime }
  let exLogger = logException logHandle au
      keys     = HandshakeKeys is rs re

  serve HostAny port $ \(s, ip) -> do
    let clientReceiver = fromSocketTimeout 120000000 s 4096
        clientSender   = toSocket s

    handle (exLogger ip) $ processHandshake keys (clientReceiver, clientSender)

openLog :: FilePath -> IO LoggerSet
openLog file = do
  _ <- setFileCreationMask 0o000
  newFileLoggerSet 1 file

logException :: LoggerSet
             -> IO ByteString
             -> SockAddr
             -> SomeException
             -> IO ()
logException ls getCachedDate ip ex = do
  zdt <- getCachedDate
  (pushLogStr ls . toLogStr) . (`append` "\n") . encode $
    object [ "date"      .= unpack zdt
           , "exception" .= displayException ex
           , "ip"        .= show ip
           ]

getDateTime :: IO ByteString
getDateTime = epochTime >>= formatUnixTime "%Y-%m-%d %H:%M:%S %z" . fromEpochTime
