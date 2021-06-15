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
import Math.NumberTheory.Powers.Squares
import Codec.Crypto.RSA.Pure



prim n = read ((splitOn " " $ show (P.nextPrime n)) !! 1)::Integer

nsifc n base tries = (div n out, out)
	where
	primesc = nub $ sort $ map prim [1..n]	
	out = head $ filter (\x-> x/=1 && x/=2) $ map (\x-> gcd (n) (tryperiod ((n)) ((n)^2-x^2) x)) $ [2^base..2^base+tries]

sp s l = nub $ sort $  concat $ map (\x-> map (\y-> x*y) (map (\e-> prim (e*2) ) [(s)..(s)+l]) ) (map (\t-> prim (t*3)) [0,(s)..(s)+l])




ex = 1826379812379156297616109238798712634987623891298419


tryperiod n period m = (powMod (powMod (m) ex n) (modular_inverse ex period) n) - (m)

{--
-- | Cypher 'm', and tries to uncypher using 'period' as the subgroup order
tryperiod n period m = 
   m == powMod c xe n   -- uncypher c, and test if equal to original message
   where
   c  = powMod m ex n   -- cypher m
   -- 'xe' would be the privKey, inverse of 'ex', if 'period' was a subgroup order
   xe = modular_inverse ex period
--}   
{--
primetosquare :: Integer -> [Integer]
{- | Search for squares 'o2' and check if subtracting (n - 1) is prime.  -}
primetosquare n = candidates ini (ini^2)
   where
   ini = integerSquareRoot (n + 1)
   candidates i i2
      -- | i > limit    = []
      | isPrime x = x : candidates o o2
      | otherwise = candidates o o2
      where 
      o  = i + 1
      o2 = i2 + i + o   -- o2 = (i + 1)^2 = i^2 + i + (i + 1)
      x  = o2 - n + 1   -- (n - 1 + x) must be a perfect square 

--}
--
--
main = do  
    args <- getArgs                  -- IO [String]
    progName <- getProgName          -- IO String
    print args
    let (n : st :  m : _) = args
    -- let n = args !! 0
    -- let st = args !! 1
    -- let e = args !! 2
    -- let m = args !! 3

    let (factorA,factorB) = nsifc (read n::Integer) (read st::Integer) (read m::Integer)
    
    putStrLn "Public Key" 
    
    print $ (read n::Integer)

    putStrLn $ "Factors"

    print $ "P " ++ show factorB

    print $ "Q " ++ show factorA
    
    putStrLn $ "Prime grimoire spells  v0.1"

