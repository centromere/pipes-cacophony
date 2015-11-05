{-# LANGUAGE FlexibleInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Instances where

import Data.ByteString (ByteString, pack)

import Test.QuickCheck

instance Arbitrary ByteString where
  arbitrary = pack <$> arbitrary
