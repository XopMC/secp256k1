# secp256k1
C# Fastest Library for Secp256k1 Bitcoin curve to do fast ECC calculation

Ported from - https://github.com/iceland2k14/secp256k1

Example usage:
```
using secp256k1;
using System;
using System.Diagnostics;

namespace Test_secp256k1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();
            secp256k1.secp256k1 testing = new secp256k1.secp256k1();
            testing.InitSecp256Lib();
            string PVK = "0000000000000000000000000000000000000000000000000000000000008344"; //hex
            stopwatch.Start();
            Console.WriteLine(BytesToHexString(testing.PrivateKeyToH160(0, false, PVK))); //uncompressed hash160
            Console.WriteLine(BytesToHexString(testing.PrivateKeyToH160(0, true, PVK))); //compressed hash160
            Console.WriteLine(BytesToHexString(testing.PrivateKeyToH160(1, true, PVK)));//segwit (double compressed) hash160
            Console.WriteLine(testing.PrivateKeyToEthAddress(PVK));//ETH addr
            stopwatch.Stop();
            long elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
            Console.WriteLine($"Completed at {elapsedMilliseconds} Milliseconds.");
        }
        static string BytesToHexString(byte[] byteArray)
        {
            string hexString = "";
            foreach (byte b in byteArray)
            {
                hexString += b.ToString("X2").ToLowerInvariant(); // X2 указывает на двузначное шестнадцатеричное число
            }
        }
    }
}
```
