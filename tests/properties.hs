module Main where

import Imports

import qualified Handshakes

tests :: TestTree
tests = testGroup "pipes-cacophony"
  [ Handshakes.tests
  ]

main :: IO ()
main = defaultMain tests
