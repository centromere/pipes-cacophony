{-# LANGUAGE OverloadedStrings #-}
----------------------------------------------------------------
-- |
-- Module      : Pipes.Noise
-- Maintainer  : John Galt <jgalt@centromere.net>
-- Stability   : experimental
-- Portability : POSIX

module Pipes.Noise
  ( -- * Types
    InboundNoisePipe
  , OutboundNoisePipe
    -- * Pipes
  , mkNoisePipes
  ) where

import Control.Concurrent.MVar (MVar, newMVar, putMVar, takeMVar)
import Control.Exception       (SomeException)
import Data.ByteString         (ByteString)
import Pipes                   (Pipe, MonadIO, await, yield, liftIO)

import Crypto.Noise.Cipher     (Cipher)
import Crypto.Noise.DH         (DH)
import Crypto.Noise.Hash       (Hash)
import Crypto.Noise
import Data.ByteArray.Extend

-- | Pipe used for inbound Noise messages.
type InboundNoisePipe  = Pipe ByteString ScrubbedBytes

-- | Pipe used for outbound Noise messages.
type OutboundNoisePipe = Pipe ScrubbedBytes ByteString

-- | Creates a pair of Pipes, the first used for inbound messages and the
--   second used for outbound messages.
mkNoisePipes :: (MonadIO m, Cipher c, DH d, Hash h)
             => NoiseState c d h
             -> IO (InboundNoisePipe  m (Either SomeException ()),
                    OutboundNoisePipe m (Either SomeException ()))
mkNoisePipes ns = do
  nsmv <- liftIO . newMVar $ ns
  return (inboundPipe nsmv, outboundPipe nsmv)

inboundPipe :: (MonadIO m, Cipher c, DH d, Hash h)
            => MVar (NoiseState c d h)
            -> InboundNoisePipe m (Either SomeException ())
inboundPipe nsmv = do
  msg <- await

  ns <- liftIO . takeMVar $ nsmv
  case readMessage ns msg of
    Left e -> return . Left $ e
    Right (pt, ns') -> do
      liftIO . putMVar nsmv $ ns'
      yield pt
      inboundPipe nsmv

outboundPipe :: (MonadIO m, Cipher c, DH d, Hash h)
             => MVar (NoiseState c d h)
             -> OutboundNoisePipe m (Either SomeException ())
outboundPipe nsmv = do
  msg <- await

  ns <- liftIO . takeMVar $ nsmv
  case writeMessage ns msg of
    Left e -> return . Left $ e
    Right (ct, ns') -> do
      liftIO . putMVar nsmv $ ns'
      yield ct
      outboundPipe nsmv
