using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Numerics;

namespace secp256k1
{
    public class secp256k1
    {
        private const string libFile = "ice_secp256k1.so";
        private const string DllPath = "ice_secp256k1.dll";
        private static bool isLinux = false;
        private static readonly BigInteger N = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337");


        //# Coin type
        //COIN_BTC  = 0
        //COIN_BSV  = 1
        //COIN_BTCD = 2
        //COIN_ARG  = 3
        //COIN_AXE  =	4
        //COIN_BC   = 5
        //COIN_BCH  = 6
        //COIN_BSD  =	7
        //COIN_BTDX = 8 
        //COIN_BTG  =	9
        //COIN_BTX  =	10
        //COIN_CHA  =	11
        //COIN_DASH = 12
        //COIN_DCR  =	13
        //COIN_DFC  =	14
        //COIN_DGB  =	15
        //COIN_DOGE = 16
        //COIN_FAI  =	17
        //COIN_FTC  =	18
        //COIN_GRS  =	19
        //COIN_JBS  =	20
        //COIN_LTC  =	21
        //COIN_MEC  =	22
        //COIN_MONA = 23
        //COIN_MZC  =	24
        //COIN_PIVX = 25
        //COIN_POLIS= 26
        //COIN_RIC  = 27
        //COIN_STRAT= 28
        //COIN_SMART= 29
        //COIN_VIA  = 30
        //COIN_XMY  =	31
        //COIN_ZEC  =	32
        //COIN_ZCL  =	33
        //COIN_ZERO = 34
        //COIN_ZEN  =	35
        //COIN_TENT = 36
        //COIN_ZEIT = 37
        //COIN_VTC  =	38
        //COIN_UNO  =	39
        //COIN_SKC  =	40
        //COIN_RVN  =	41
        //COIN_PPC  =	42
        //COIN_OMC  =	43
        //COIN_OK   =	44
        //COIN_NMC  =	45
        //COIN_NLG  =	46
        //COIN_LBRY =	47
        //COIN_DNR  =	48
        //COIN_BWK  =	49
        // type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
        static void Initialization()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                //libFile = "ice_secp256k1.dll";
                isLinux = false;
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                //libFile = "ice_secp256k1.so";
                isLinux = true;
            }
            else
            {
                Console.WriteLine("[-] Unsupported Platform currently for dll method. Only [Windows and Linux] is working");
                Environment.Exit(1);
            }
        }

        private static class IceLibrary_linux

        {
            [DllImport(libFile)]
            public static extern void get_x_to_y(byte[] x, bool isEven, byte[] ret);

            [DllImport(libFile)]
            public static extern void pbkdf2_hmac_sha512_dll(IntPtr ret, IntPtr words, int len);

            [DllImport(libFile)]
            public static extern void pbkdf2_hmac_sha512_list(IntPtr ret, IntPtr words, ulong wordsLen, int mnemSize, ulong total);


            [DllImport(libFile)]
            public static extern IntPtr scalar_multiplication(byte[] pvk, byte[] ret);

            [DllImport(libFile)]
            public static extern IntPtr scalar_multiplications(byte[] pvks, int len, byte[] ret);


            [DllImport(libFile)]
            public static extern IntPtr privatekey_to_coinaddress(int coinType, int addrType, bool isCompressed, string pvkInt);

            [DllImport(libFile)]
            public static extern IntPtr privatekey_to_address(int addrType, bool isCompressed, string pvkInt);

            [DllImport(libFile)]
            public static extern IntPtr hash_to_address(int addrType, bool isCompressed, string hash);

            [DllImport(libFile)]
            public static extern IntPtr pubkey_to_address(int addrType, bool isCompressed, string pubkey);

            [DllImport(libFile)]
            public static extern void privatekey_to_h160(int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(libFile)]
            public static extern void privatekey_loop_h160(ulong num, int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(libFile)]
            public static extern void privatekey_loop_h160_sse(ulong num, int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(libFile)]
            public static extern void pubkey_to_h160(int addrType, bool isCompressed, byte[] pubkey, byte[] ret);

            [DllImport(libFile)]
            public static extern void pub_endo1(string pubkey, byte[] ret);

            [DllImport(libFile)]
            public static extern void pub_endo2(string pubkey, byte[] ret);

            [DllImport(libFile)]
            public static extern IntPtr b58_encode(byte[] input);

            [DllImport(libFile)]
            public static extern IntPtr b58_decode(string addr);

            [DllImport(libFile)]
            public static extern void bech32_address_decode(int coinType, string b32Addr, byte[] h160);

            [DllImport(libFile)]
            public static extern void get_sha256(byte[] input, int len, byte[] ret);

            [DllImport(libFile)]
            public static extern IntPtr pubkeyxy_to_ETH_address(string upubXY);

            [DllImport(libFile)]
            public static extern void pubkeyxy_to_ETH_address_bytes(string upubXY, byte[] ret);

            [DllImport(libFile)]
            public static extern IntPtr privatekey_to_ETH_address(string pvk);

            [DllImport(libFile)]
            public static extern void privatekey_to_ETH_address_bytes(string pvk, byte[] ret);

            [DllImport(libFile)]
            public static extern IntPtr privatekey_group_to_ETH_address(string pvk, int m);

            [DllImport(libFile)]
            public static extern void privatekey_group_to_ETH_address_bytes(string pvk, int m, byte[] ret);

            [DllImport(libFile)]
            public static extern void init_P2_Group(string upub);

            [DllImport(libFile)]
            public static extern void init_secp256_lib();

            [DllImport(libFile)]
            public static extern void free_memory(IntPtr pointer);
        }
        private static class IceLibrary
        {
            [DllImport(DllPath)]
            public static extern void get_x_to_y(byte[] x, bool isEven, byte[] ret);

            [DllImport(DllPath)]
            public static extern void pbkdf2_hmac_sha512_dll(IntPtr ret, IntPtr words, int len);

            [DllImport(DllPath)]
            public static extern void pbkdf2_hmac_sha512_list(IntPtr ret, IntPtr words, ulong wordsLen, int mnemSize, ulong total);


            [DllImport(DllPath)]
            public static extern IntPtr scalar_multiplication(byte[] pvk, byte[] ret);

            [DllImport(DllPath)]
            public static extern IntPtr scalar_multiplications(byte[] pvks, int len, byte[] ret);


            [DllImport(DllPath)]
            public static extern IntPtr privatekey_to_coinaddress(int coinType, int addrType, bool isCompressed, string pvkInt);

            [DllImport(DllPath)]
            public static extern IntPtr privatekey_to_address(int addrType, bool isCompressed, string pvkInt);

            [DllImport(DllPath)]
            public static extern IntPtr hash_to_address(int addrType, bool isCompressed, string hash);

            [DllImport(DllPath)]
            public static extern IntPtr pubkey_to_address(int addrType, bool isCompressed, string pubkey);

            [DllImport(DllPath)]
            public static extern void privatekey_to_h160(int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(DllPath)]
            public static extern void privatekey_loop_h160(ulong num, int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(DllPath)]
            public static extern void privatekey_loop_h160_sse(ulong num, int addrType, bool isCompressed, string pvkInt, byte[] ret);

            [DllImport(DllPath)]
            public static extern void pubkey_to_h160(int addrType, bool isCompressed, byte[] pubkey, byte[] ret);

            [DllImport(DllPath)]
            public static extern void pub_endo1(string pubkey, byte[] ret);

            [DllImport(DllPath)]
            public static extern void pub_endo2(string pubkey, byte[] ret);

            [DllImport(DllPath)]
            public static extern IntPtr b58_encode(byte[] input);

            [DllImport(DllPath)]
            public static extern IntPtr b58_decode(string addr);

            [DllImport(DllPath)]
            public static extern void bech32_address_decode(int coinType, string b32Addr, byte[] h160);

            [DllImport(DllPath)]
            public static extern void get_sha256(byte[] input, int len, byte[] ret);

            [DllImport(DllPath)]
            public static extern IntPtr pubkeyxy_to_ETH_address(string upubXY);

            [DllImport(DllPath)]
            public static extern void pubkeyxy_to_ETH_address_bytes(string upubXY, byte[] ret);

            [DllImport(DllPath)]
            public static extern IntPtr privatekey_to_ETH_address(string pvk);

            [DllImport(DllPath)]
            public static extern void privatekey_to_ETH_address_bytes(string pvk, byte[] ret);

            [DllImport(DllPath)]
            public static extern IntPtr privatekey_group_to_ETH_address(string pvk, int m);

            [DllImport(DllPath)]
            public static extern void privatekey_group_to_ETH_address_bytes(string pvk, int m, byte[] ret);

            [DllImport(DllPath)]
            public static extern void init_P2_Group(string upub);

            [DllImport(DllPath)]
            public static extern void init_secp256_lib();

            [DllImport(DllPath)]
            public static extern void free_memory(IntPtr pointer);
        }


        public (byte[], byte[]) PvkToPubs_Bytes(string pvkHex)
        {
            if (BigInteger.TryParse(pvkHex, System.Globalization.NumberStyles.HexNumber, null, out BigInteger pvkInt))
            {
                if (pvkInt < 0) pvkInt = N + pvkInt;
                //string[] PVKs = new string[1];
                //PVKs[0] = Fl(pvkInt);

                byte[] UPub = _scalar_multiplication(Fl(pvkInt));
                byte[] Cpub = PointToCPub(UPub);
                return (UPub, Cpub);

            }
            throw new ArgumentException("Invalid hex string.", nameof(pvkHex));

        }

        public (string, string) PvkToPubs(string pvkHex)
        {
            if (BigInteger.TryParse(pvkHex, System.Globalization.NumberStyles.HexNumber, null, out BigInteger pvkInt))
            {
                if (pvkInt < 0) pvkInt = N + pvkInt;
                //string[] PVKs = new string[1];
                //PVKs[0] = Fl(pvkInt);

                byte[] UPub = _scalar_multiplication(Fl(pvkInt));
                string Cpub = PointToCPub(UPub, false);
                return (BytesToHexString(UPub), Cpub);

            }
            throw new ArgumentException("Invalid hex string.", nameof(pvkHex));

        }

        private byte[] _scalar_multiplication(string pvkHex)
        {
            Encoding utf8 = Encoding.UTF8;
            byte[] res = new byte[65];
            byte[] pvk = utf8.GetBytes(pvkHex);//HexStringToByteArray(pvkHex);
            if (isLinux)
            { IceLibrary_linux.scalar_multiplication(pvk, res); }
            else 
            { IceLibrary.scalar_multiplication(pvk, res); }
            //Console.WriteLine( BytesToHexString(pvk));
            return res;
        }

        public byte[] ScalarMultiplication(string pvkHex)
        {
            if (BigInteger.TryParse(pvkHex, System.Globalization.NumberStyles.HexNumber, null, out BigInteger pvkInt))
            {
                if (pvkInt < 0) pvkInt = N + pvkInt;
                //string[] PVKs = new string[1];
                //PVKs[0] = Fl(pvkInt);

                return _scalar_multiplication(Fl(pvkInt));
                
            }
            throw new ArgumentException("Invalid hex string.", nameof(pvkHex));
        }

        private byte[] _scalar_multiplications(string[] pvkHexList)
        {
            Encoding utf8 = Encoding.UTF8;
            int sz = pvkHexList.Length;
            byte[] res = new byte[65 * sz];
            byte[] pvks = new byte[65 * sz];
            for (int i = 0; i < sz; i++)
            {
                byte[] pvkBytes = utf8.GetBytes(pvkHexList[i]);
                Array.Copy(pvkBytes, 0, pvks, i * 65, 65);
            }
            if (isLinux)
            {
                IceLibrary_linux.scalar_multiplications(pvks, sz, res);
            }
            else
            {
                IceLibrary.scalar_multiplications(pvks, sz, res);

            }
            //Console.WriteLine(BytesToHexString(pvks));
            return res;
        }

        public byte[] ScalarMultiplications(string[] pvkHexList)
        {
            string[] normalizedPvkHexList = new string[pvkHexList.Length];
            for (int i = 0; i < pvkHexList.Length; i++)
            {
                if (int.TryParse(pvkHexList[i], System.Globalization.NumberStyles.HexNumber, null, out int pvkInt))
                {
                    normalizedPvkHexList[i] = pvkInt < 0 ? Fl(N + pvkInt) : Fl(pvkInt);
                }
                else
                {
                    throw new ArgumentException("Invalid hex string in the list.", nameof(pvkHexList));
                }
            }
            return _scalar_multiplications(normalizedPvkHexList);
        }

        //private string Fl(BigInteger sstr, int length = 64)
        //{
        //    if (sstr < 0) sstr = N + sstr;
        //    return sstr.ToString("x").PadLeft(length, '0');
        //}

        public string Fl(object sstr, int length = 64)
        {
            string fixedStr = "";

            if (sstr is int intValue)
            {
                fixedStr = intValue.ToString("x").PadLeft(length, '0');
            }
            if (sstr is BigInteger BigValue)
            {
                fixedStr = BigValue.ToString("x").PadLeft(length, '0');
            }
            else if (sstr is string strValue)
            {
                if (strValue.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    fixedStr = strValue.Substring(2).PadLeft(length, '0');
                }
                else
                {
                    fixedStr = strValue.PadLeft(length, '0');
                }
            }
            else if (sstr is byte[] bytesValue)
            {
                byte[] fixedBytes = new byte[length];
                Array.Copy(bytesValue, 0, fixedBytes, length - bytesValue.Length, bytesValue.Length);
                return BytesToHexString(fixedBytes);
            }
            else
            {
                Console.WriteLine("[Error] Input format [Integer] [Hex] [Bytes] allowed only. Detected : " + sstr.GetType());
            }
            //Console.WriteLine( fixedStr);
            return fixedStr;
        }

        private byte[] HexStringToByteArray(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have an even number of characters.");
            }

            byte[] byteArray = new byte[hex.Length / 2];
            for (int i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return byteArray;
        }

        public string PrivateKeyToCoinAddress(int coinType, int addrType, bool isCompressed, string pvkInt)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.privatekey_to_coinaddress(coinType, addrType, isCompressed, pvkInt);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.privatekey_to_coinaddress(coinType, addrType, isCompressed, pvkInt);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public string PrivateKeyToAddress(int addrType, bool isCompressed, string pvkInt)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.privatekey_to_address(addrType, isCompressed, pvkInt);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.privatekey_to_address(addrType, isCompressed, pvkInt);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public string HashToAddress(int addrType, bool isCompressed, string hash)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.hash_to_address(addrType, isCompressed, hash);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.hash_to_address(addrType, isCompressed, hash);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public string PubKeyToAddress(int addrType, bool isCompressed, string pubkey)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.pubkey_to_address(addrType, isCompressed, pubkey);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.pubkey_to_address(addrType, isCompressed, pubkey);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public byte[] PrivateKeyToH160(int addrType, bool isCompressed, string pvkInt)
        {
            if (isLinux)
            {
                byte[] h160 = new byte[20];
                IceLibrary_linux.privatekey_to_h160(addrType, isCompressed, pvkInt, h160);
                return h160;
            }
            else
            {
                byte[] h160 = new byte[20];
                IceLibrary.privatekey_to_h160(addrType, isCompressed, pvkInt, h160);
                return h160;

            }
        }

        public byte[] PrivateKeyLoopH160(ulong num, int addrType, bool isCompressed, string pvkInt)
        {
            if (isLinux)
            {
                byte[] h160 = new byte[20 * num];
                IceLibrary_linux.privatekey_loop_h160(num, addrType, isCompressed, pvkInt, h160);
                return h160;
            }
            else
            {

                byte[] h160 = new byte[20 * num];
                IceLibrary.privatekey_loop_h160(num, addrType, isCompressed, pvkInt, h160);
                return h160;
            }
        }

        public byte[] PrivateKeyLoopH160SSE(ulong num, int addrType, bool isCompressed, string pvkInt)
        {
            if (isLinux)
            {
                byte[] h160 = new byte[20 * num];
                IceLibrary_linux.privatekey_loop_h160_sse(num, addrType, isCompressed, pvkInt, h160);
                return h160;
            }
            else
            {

                byte[] h160 = new byte[20 * num];
                IceLibrary.privatekey_loop_h160_sse(num, addrType, isCompressed, pvkInt, h160);
                return h160;
            }
        }

        public byte[] PubKeyToH160(int addrType, bool isCompressed, byte[] pubkey)
        {
            if (isLinux)
            {
                byte[] h160 = new byte[20];
                IceLibrary_linux.pubkey_to_h160(addrType, isCompressed, pubkey, h160);
                return h160;
            }
            else
            {
                byte[] h160 = new byte[20];
                IceLibrary.pubkey_to_h160(addrType, isCompressed, pubkey, h160);
                return h160;

            }
        }

        public byte[] PubEndo1(string pubkey)
        {
            if (isLinux)
            {
                byte[] ret = new byte[65];
                IceLibrary_linux.pub_endo1(pubkey, ret);
                return ret;
            }
            else
            {
                byte[] ret = new byte[65];
                IceLibrary.pub_endo1(pubkey, ret);
                return ret;

            }
        }

        public byte[] PubEndo2(string pubkey)
        {
            if (isLinux)
            {
                byte[] ret = new byte[65];
                IceLibrary_linux.pub_endo2(pubkey, ret);
                return ret;
            }
            else
            {
                byte[] ret = new byte[65];
                IceLibrary.pub_endo2(pubkey, ret);
                return ret;
            }
        }

        public string B58Encode(byte[] input)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.b58_encode(input);
                string encoded = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return encoded;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.b58_encode(input);
                string encoded = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return encoded;

            }
        }

        public string B58Decode(string addr)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.b58_decode(addr);
                string decoded = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return decoded;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.b58_decode(addr);
                string decoded = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return decoded;

            }
        }

        public string Bech32AddressDecode(int coinType, string b32Addr)
        {
            if (isLinux)
            {
                byte[] h160 = new byte[20];
                IceLibrary_linux.bech32_address_decode(coinType, b32Addr, h160);
                return BytesToHexString(h160);
            }
            else
            {
                byte[] h160 = new byte[20];
                IceLibrary.bech32_address_decode(coinType, b32Addr, h160);
                return BytesToHexString(h160);//BitConverter.ToString(h160).Replace("-", "").ToLower();

            }
        }

        public byte[] GetSha256(byte[] input)
        {
            if (isLinux)
            {
                byte[] ret = new byte[32];
                IceLibrary_linux.get_sha256(input, input.Length, ret);
                return ret;
            }
            else
            {

                byte[] ret = new byte[32];
                IceLibrary.get_sha256(input, input.Length, ret);
                return ret;
            }
        }

        public byte[] GetSha256(string IN)
        {
            Encoding utf8 = Encoding.UTF8;
            byte[] input = utf8.GetBytes(IN);
            if (isLinux)
            {
                byte[] ret = new byte[32];
                IceLibrary_linux.get_sha256(input, input.Length, ret);
                return ret;
            }
            else
            {

                byte[] ret = new byte[32];
                IceLibrary.get_sha256(input, input.Length, ret);
                return ret;
            }
        }
        public byte[] Checksum(byte[] input)
        {
            byte[] res = GetSha256(input);
            byte[] res2 = GetSha256(res);
            return new Span<byte>(res2, 0, 4).ToArray();
        }

        public byte[] Checksum(string input)
        {
            byte[] res = GetSha256(input);
            byte[] res2 = GetSha256(res);
            return new Span<byte>(res2, 0, 4).ToArray();
        }

        public string PubKeyToEthAddress(string pubkey)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.pubkeyxy_to_ETH_address(pubkey);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.pubkeyxy_to_ETH_address(pubkey);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public byte[] PubKeyToEthAddressBytes(string pubkey)
        {
            if (isLinux)
            {
                byte[] ret = new byte[20];
                IceLibrary_linux.pubkeyxy_to_ETH_address_bytes(pubkey, ret);
                return ret;
            }
            else
            {
                byte[] ret = new byte[20];
                IceLibrary.pubkeyxy_to_ETH_address_bytes(pubkey, ret);
                return ret;
            }
        }

        public string PrivateKeyToEthAddress(string pvk)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary_linux.privatekey_to_ETH_address(pvk);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return address;
            }
            else
            {
                IntPtr resultPtr = IceLibrary.privatekey_to_ETH_address(pvk);
                string address = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return address;

            }
        }

        public byte[] PrivateKeyToEthAddressBytes(string pvk)
        {
            if (isLinux)
            {
                byte[] ret = new byte[20];
                IceLibrary_linux.privatekey_to_ETH_address_bytes(pvk, ret);
                return ret;
            }
            else
            {
                byte[] ret = new byte[20];
                IceLibrary.privatekey_to_ETH_address_bytes(pvk, ret);
                return ret;
            }
        }

        public string PrivateKeyGroupToEthAddress(string pvk, int m)
        {
            if (isLinux)
            {
                IntPtr resultPtr = IceLibrary.privatekey_group_to_ETH_address(pvk, m);
                string addresses = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary.free_memory(resultPtr);
                return addresses;
            }
            else
            {
                IntPtr resultPtr = IceLibrary_linux.privatekey_group_to_ETH_address(pvk, m);
                string addresses = Marshal.PtrToStringAnsi(resultPtr);
                IceLibrary_linux.free_memory(resultPtr);
                return addresses;
            }
        }

        public byte[] PrivateKeyGroupToEthAddressBytes(string pvk, int m)
        {
            if (isLinux)
            {
                byte[] ret = new byte[20 * m];
                IceLibrary_linux.privatekey_group_to_ETH_address_bytes(pvk, m, ret);
                return ret;
            }
            else
            {
                byte[] ret = new byte[20 * m];
                IceLibrary.privatekey_group_to_ETH_address_bytes(pvk, m, ret);
                return ret;

            }
        }

        public byte[] Pbkdf2HmacSha512Dll(string words)
        {
            if (isLinux)
            {
                byte[] seedBytes = new byte[64];
                IntPtr seedPtr = Marshal.AllocHGlobal(seedBytes.Length);
                IntPtr wordsPtr = Marshal.StringToHGlobalAnsi(words);

                IceLibrary_linux.pbkdf2_hmac_sha512_dll(seedPtr, wordsPtr, words.Length);

                Marshal.Copy(seedPtr, seedBytes, 0, seedBytes.Length);

                Marshal.FreeHGlobal(seedPtr);
                Marshal.FreeHGlobal(wordsPtr);

                return seedBytes;
            }
            else
            {
                byte[] seedBytes = new byte[64];
                IntPtr seedPtr = Marshal.AllocHGlobal(seedBytes.Length);
                IntPtr wordsPtr = Marshal.StringToHGlobalAnsi(words);

                IceLibrary.pbkdf2_hmac_sha512_dll(seedPtr, wordsPtr, words.Length);

                Marshal.Copy(seedPtr, seedBytes, 0, seedBytes.Length);

                Marshal.FreeHGlobal(seedPtr);
                Marshal.FreeHGlobal(wordsPtr);

                return seedBytes;
            }
        }

        public byte[] Pbkdf2HmacSha512List(string[] wordsList)
        {
            if (isLinux)
            {
                int wl = wordsList.Length;
                int strength = wordsList[0].Split().Length;
                string words = string.Join(" ", wordsList);
                byte[] seedBytes = new byte[64 * wl];

                IntPtr seedPtr = Marshal.AllocHGlobal(seedBytes.Length);
                IntPtr wordsPtr = Marshal.StringToHGlobalAnsi(words);

                IceLibrary_linux.pbkdf2_hmac_sha512_list(seedPtr, wordsPtr, (ulong)words.Length, strength, (ulong)wl);

                Marshal.Copy(seedPtr, seedBytes, 0, seedBytes.Length);

                Marshal.FreeHGlobal(seedPtr);
                Marshal.FreeHGlobal(wordsPtr);

                return seedBytes;
            }
            else
            {
                int wl = wordsList.Length;
                int strength = wordsList[0].Split().Length;
                string words = string.Join(" ", wordsList);
                byte[] seedBytes = new byte[64 * wl];

                IntPtr seedPtr = Marshal.AllocHGlobal(seedBytes.Length);
                IntPtr wordsPtr = Marshal.StringToHGlobalAnsi(words);

                IceLibrary.pbkdf2_hmac_sha512_list(seedPtr, wordsPtr, (ulong)words.Length, strength, (ulong)wl);

                Marshal.Copy(seedPtr, seedBytes, 0, seedBytes.Length);

                Marshal.FreeHGlobal(seedPtr);
                Marshal.FreeHGlobal(wordsPtr);

                return seedBytes;
            }



        }
        public string ToCPub(string pubHex)
        {
            string P = pubHex;
            if (pubHex.Length > 70)
            {
                P = (BigInteger.Parse(pubHex.Substring(66), System.Globalization.NumberStyles.HexNumber) % 2 == 0 ? "02" : "03") + pubHex.Substring(2, 64);

            }
            return P;
        }

        public dynamic PointToCPub(byte[] pubkeyBytes, bool returnByteArray = true)
        {
            string P = BytesToHexString(pubkeyBytes);
            if (P.Length > 70)
            {
                string x = P.Substring(2, 64);
                string y = P.Substring(66);
                P = (BigInteger.Parse(y, System.Globalization.NumberStyles.HexNumber) % 2 == 0 ? "02" : "03") + x;
            }
            if (returnByteArray)
            {
                return StringToByteArray(P);
            }
            else
            {
                return P;
            }
        }

        public byte[] PubToUPub(string pubHex)
        {
            Encoding utf8 = Encoding.UTF8;
            string x = pubHex.Substring(2, 64);
            string y;
            if (pubHex.Length < 70)
            {
                bool isEven = BigInteger.Parse(pubHex.Substring(0, 2), System.Globalization.NumberStyles.HexNumber) % 2 == 0;
                y = BytesToHexString(GetXToY(utf8.GetBytes(x), isEven)).PadLeft(64, '0');
            }
            else
            {
                y = pubHex.Substring(66).PadLeft(64, '0');
            }

            //Console.WriteLine("04" + x + y);
            return StringToByteArray("04" + x + y);
        }


        public byte[] GetXToY(byte[] xBytes, bool isEven)
        {
            if (isLinux)
            {
                byte[] res = new byte[32];
                IceLibrary_linux.get_x_to_y(xBytes, isEven, res);
                return res;
            }
            else
            {
                byte[] res = new byte[32];
                IceLibrary.get_x_to_y(xBytes, isEven, res);
                return res;

            }
        }

        public byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public void InitP2Group(string pubkeyBytes)
        {
            if (isLinux)
            {
                IceLibrary_linux.init_P2_Group(pubkeyBytes);
            }
            else
            {
                IceLibrary.init_P2_Group(pubkeyBytes);
            }
        }

        static string BytesToHexString(byte[] byteArray)
        {
            string hexString = "";
            foreach (byte b in byteArray)
            {
                hexString += b.ToString("X2").ToLowerInvariant(); // X2 указывает на двузначное шестнадцатеричное число
            }
            return hexString;
        }

        public void InitSecp256Lib()
        {
            Initialization();
            if (isLinux)
            {
                IceLibrary_linux.init_secp256_lib();
            }
            else
            {
                IceLibrary.init_secp256_lib();

            }
        }

    }
}