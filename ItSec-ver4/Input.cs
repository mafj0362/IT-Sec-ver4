using System;
using System.Text.Json;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace ItSec_ver4
{
    class Input
    {
        public void Välkommen()
        {
            string clientFile = "";
            string serverFile = "";
            string readFile = "";
            string masterpassword = "allan";
            Console.WriteLine("Ange lösenord: ");
            string input = Console.ReadLine();
        }

        //skapar en clientdict, i den dicten ska det läggas till en superkey.
        static void Init(string clientFile, string serverFile, string masterpwd)
        {
            //generear en IV samt sparar i en sträng
            byte[] iv = Kryptering.GenerateIV();
            string ivstring = Convert.ToBase64String(iv);

            //vaultdict
            Dictionary<string, string> vautlDict = new Dictionary<string, string>();
            string vaultDictString = JsonSerializer.Serialize(vautlDict);

            //generear en sk samt sparar i en sträng
            byte[] secretkey = Kryptering.GenerateSecretKey();
            string secretkeystring = Convert.ToBase64String(secretkey);

            byte[] vaultkey = Kryptering.GenerateVaultKey(masterpwd, secretkey);


            //Krypterar valvet
            byte[] encVault = Kryptering.EncryptStringToBytes_Aes(vaultDictString, vaultkey, iv);
            string encVaultString = Convert.ToBase64String(encVault);

            //Vault
            Dictionary<string, string> vault = new Dictionary<string, string>();
            string jsonVault = JsonSerializer.Serialize(vault);

            //Skapar Clientdict
            Dictionary<string, string> clientDict = new Dictionary<string, string>();
            clientDict.Add("Secret key", secretkeystring);

            string clientContent = JsonSerializer.Serialize(clientDict);
            File.AppendAllText(clientFile + ".txt", clientContent);

            //Skapar Serverdict
            //byte[] encryptedVault = Kryptering.EncryptStringToBytes_Aes(jsonVault, vaultkey, iv);
            //string encryptedVaultString = Convert.ToBase64String(encryptedVault);

            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            serverDict.Add("Vault", encVaultString);
            serverDict.Add("IV", ivstring);


            string serverContent = JsonSerializer.Serialize(serverDict);
            File.AppendAllText(serverFile + ".txt", serverContent);

            File.AppendAllText(clientFile + ".txt", secretkeystring);

            using (StreamWriter clientwriter = new StreamWriter(clientFile, true))
            {
                clientwriter.Write(secretkeystring);

            }
            using (StreamWriter serverwriter = new StreamWriter(serverFile, true))
            {
                serverwriter.Write(serverContent);

            }

            Console.WriteLine(secretkeystring);
        }

        static void Create(string clientFile, string serverFile, string masterpwd, string secretkey)
        {
            try
            {

                Dictionary<string, string> newClientDict = new Dictionary<string, string>();
                newClientDict.Add("SecretKey", secretkey);

                string newClient = JsonSerializer.Serialize(newClientDict);

                using (StreamWriter writer = File.CreateText(clientFile))
                {
                    writer.Write(newClient);
                }

                string serverDictString = File.ReadAllText(serverFile);
                var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverDictString);
                string ivstring = serverDict["IV"];
                byte[] IVbyte = Convert.FromBase64String(ivstring);

                // Decrypt the vault using the provided password, secret key, and IV.
                string encryptedVault = File.ReadAllText(serverFile);
                byte[] encryptedBytes = Convert.FromBase64String(encryptedVault);

                using (Aes aes = Aes.Create())
                {


                    aes.Key = Convert.FromBase64String(secretkey);
                    aes.IV = IVbyte;
                    aes.Mode = CipherMode.CBC;

                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

                    string decryptedVault = Encoding.UTF8.GetString(decryptedBytes);
                    Dictionary<string, string> decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(decryptedVault);

                    // Encrypt the vault using the new client file and write it to the server file.
                    string clientVault = JsonSerializer.Serialize(decryptVaultDict);

                    byte[] clientBytes = Encoding.UTF8.GetBytes(clientVault);

                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    byte[] encryptedClientBytes = encryptor.TransformFinalBlock(clientBytes, 0, clientBytes.Length);

                    string encryptedClientVault = Convert.ToBase64String(encryptedClientBytes);
                    File.WriteAllText(serverFile, encryptedClientVault);
                }

                Console.WriteLine("Success");
            }
            catch
            {
                File.Delete(clientFile);
                Console.WriteLine("Wrong password or secretkey!");
            }
        }

        static void Get()
        {

        }
        static void Set(string clientFile, string serverFile, string masterpwd, string prop)
        {

        }


    }
}
