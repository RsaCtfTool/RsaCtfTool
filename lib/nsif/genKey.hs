{-# LANGUAGE FlexibleContexts #-}

--Nos Santos Izquierdo Field , PRIME GRIMOIRE SPELLS v0.0.0.2
-- Authors
--  Enrique Santos
--  Vicent Nos

module Main where

import System.Environment
import System.Exit
import System.Console.CmdArgs

import Data.List.Ordered
import Data.List.Split 
import Data.List (subsequences)

import Data.Numbers.Primes
import qualified Math.NumberTheory.Primes as P
import Math.NumberTheory.ArithmeticFunctions
import Math.NumberTheory.Powers.Modular
-- import Math.NumberTheory.Powers.Squares
-- import Math.NumberTheory.Powers
import Math.NumberTheory.Roots
import Codec.Crypto.RSA.Pure


prim, primb :: Integer -> Integer
prim = P.unPrime . P.nextPrime 
primb = P.unPrime . P.precPrime







--
main = do  
    args <- getArgs                  -- IO [String]
    progName <- getProgName          -- IO String
    print args
    let (n : st :  m : e) = args
    -- let n = args !! 0
    -- let st = args !! 1
    -- let e = args !! 2
    -- let m = args !! 3

    let n =  
    
    

    print $ "PublicKey " ++ show n
    
    putStrLn $ "Prime grimoire spells  v0.1"

