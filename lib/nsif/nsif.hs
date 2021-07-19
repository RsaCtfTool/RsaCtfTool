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

nsi n r2 b e 
	| n == n2 = (r1,r2)
	| otherwise = nsi n (r2-1) b e
	where
	r1 = div (n - (b^e*(b^e+r2))) (b^e+r2)
	-- r1 = 1
	n2 = (r1 + b^e )*(b^e + r2)


ncr n b e t = head $ filter (\(_,w)-> w/=1 && w/=n ) 
   $ map (\x-> (n, (gcd n ((powMod x (n^2 - x^2) n) - x ))) ) 
   $ map (\x-> x + 3)  [0 .. t] -- [(e^b..e^b+t] 


loadprimes = do 
   a <- readFile "../../../safes25.txt"
   let b = splitOn "\n" a
   let c = init $ map (\x-> read x::Integer) b

   return c


powRoot = minimum . intpowroot


bestroot n = minimum $ filter (\(_,e,_)-> e /= n ) 
   $ map (\x-> (n - (integerRoot x n)^x, (integerRoot x n), x) ) [1 .. 1000]

powDiv n o
   | rest <= 2 = (b,e) : o
   | otherwise = powDiv rest ((b,e) : o)
   where
   (rest,b,e) = bestroot n
      

intpowroot n =  filter (\(_,f,g)-> f^g <= n) 
   $ concatMap (\x-> map (\y-> (n - x^y, x, y) ) [2 .. 512]) [2 .. 512]


{- | Returns all the perfect powers of the bitlength 'b' -}
bitlengthPowers b = concatMap (rangePowers (ini, 2*ini)) exponents
   where
   ini = 2^b
   exponents = takeWhile (<= b) primelist -- reverse for up-down exponents
   primelist = fmap P.unPrime primes 


{- | Returns all the `e` powers in the range [ini inclusive, end exclusive). -}
rangePowers (ini, end) e = dropWhile (< ini) . fmap (^ e)
   $ [integerRoot e ini .. integerRoot e (end - 1)]


-- loop "bit" squares
--
--
--



bestpow n = head $ filter (< n) $ map (\x-> map (\y-> y^x ) [1 .. 1000]) [1 .. 15]

-- supcar primespair o
supcar [p] o    = lcm o p
supcar (p:to) o = supcar to $ lcm o p


nsifc n tries
   | out2 /= 1 && out2 /= n = (div n out2,out2) 
   | out  /= 1 && out  /= n = (div n out, out)
   | out3 /= 1 && out3 /= n = (div n out3,out3) 
   | out4 /= 1 && out4 /= n = (div n out4,out4)
   | out5 /= 1 && out5 /= n = (div n out5,out5) 
   | out6 /= 1 && out6 /= n = (div n out6,out6)
   | out7 /= 1 && out7 /= n = (div n out7,out7) 
   | out8 /= 1 && out8 /= n = (div n out8,out8)

   | otherwise = (0,0)
   where
   base = 2
      
   --(nearsquare) = 2^(logBase 2 n)
   -- primesc = nub $ sort $ map prim [1 .. n] 
   out  = head $ reverse (1 : (filter (\r-> r/=1 && r/=2 ) $ map (\x-> gcd n (tryperiod n (x*(n + (n - x))) x)) $ reverse $ [2^base .. 2^base + tries]))
   out2 = head $ reverse (1 : (filter (\x-> x/=1 && x/=2 ) $ map (\x-> gcd n (tryperiod n (n^2 - x^2) x)) [2^base .. 2^base + tries]))

   out3 = head $ reverse (1 : (filter (\r-> r/=1 && r/=2 ) $ map (\x-> gcd n (tryperiod n (n^3 + x^3) x)) [3^base .. 3^base + tries]))
   out4 = head $ reverse (1 : (filter (\x-> x/=1 && x/=2 ) $ map (\x-> gcd n (tryperiod n (n^3 - x^3) x)) [3^base .. 3^base + tries]))
   
   out5 = head $ reverse (1 : (filter (\r-> r/=1 && r/=2 ) $ map (\x-> gcd n (tryperiod n (n^5 + x^5) x)) [5^base .. 5^base + tries]))
   out6 = head $ reverse (1 : (filter (\x-> x/=1 && x/=2 ) $ map (\x-> gcd n (tryperiod n (n^5 - x^5) x)) [5^base .. 5^base + tries]))
   
   out7 = head $ reverse (1 : (filter (\r-> r/=1 && r/=2 ) $ map (\x-> gcd n (tryperiod n (n^7 + x^7) x)) [7^base .. 7^base + tries]))
   out8 = head $ reverse (1 : (filter (\x-> x/=1 && x/=2 ) $ map (\x-> gcd n (tryperiod n (n^7 - x^7) x)) [7^base .. 7^base + tries]))




sp s l = nub $ sort $ concatMap (\x-> map (\y-> x*y) 
   (map (\e-> prim (e*2)) [  s .. s+l]) ) 
   (map (\t-> prim (t*3)) [0,s .. s+l])





ex2 = 13 
ex = 1826379812379156297616109238798712634987623891298419 :: Integer


tryperiod n period _ = (powMod 2 (ex * modular_inverse ex period - 1) n) - 1
{--
-- | Cypher 'm', and tries to uncypher using 'period' as the subgroup order
tryperiod n period m = 
   m == powMod c xe n   -- uncypher c, and test if equal to original message
   where
   c  = powMod m ex n   -- cypher m
   -- 'xe' would be the privKey, inverse of 'ex', if 'period' was a subgroup order
   xe = modular_inverse ex period
--}   

primetosquare :: Integer -> [Integer]
{- | Search for squares 'o2' and check if subtracting (n - 1) is prime.  -}
primetosquare n = candidates ini (ini^2)
   where
   ini = integerSquareRoot (n - 1)
   candidates i i2
      -- | i > limit    = []
      | isPrime x = x : candidates o o2
      | otherwise = candidates o o2
      where 
      o  = i + 1
      o2 = i2 + i + o   -- o2 = (i + 1)^2 = i^2 + i + (i + 1)
      x  = o2 - n + 1   -- (n - 1 + x) must be a perfect square 


intPowBaseExp n = head $ map (\([a,b],c)-> [show c,a]) 
   $ filter (\([_,r],_)-> r=="0")  
   $ map (\x-> (splitOn "." $ show $ logBase x n, x)) [3 .. 3000]



nsif n tries
   | d /=1 && d /= n = (div n d, d, divcar)
   | otherwise = (0,0,0)
   where
   base = 2 
      
   --(nearsquare) = 2^(logBase 2 n)
   -- primesc = nub $ sort $ map prim [1..n] 
   
   (d, divcar) = head $ reverse $ (1,1) : (filter (\(r,_)-> r/=1 ) 
      $ map (\x-> (gcd n (tryperiod n (n^2 - x^2) x), x) ) 
      [2^base .. 2^base + tries])


--
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

    let (factorA, factorB) = nsifc (read n::Integer) (read m::Integer) 
    
    putStrLn "Public Key" 
    
    print $ (read n::Integer)

    putStrLn $ "Factors"

    print $ "P " ++ show factorB

    print $ "Q " ++ show factorA
    
    putStrLn $ "Prime grimoire spells  v0.1"

