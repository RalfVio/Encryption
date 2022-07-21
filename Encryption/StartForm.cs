using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;


namespace Encryption
{
    public partial class StartForm : Form
    {
        public StartForm()
        {
            InitializeComponent();
        }

        private void CloseToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void OpenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(this.encryptionKeyTextBox.Text))
                return;

            if (openFileDialog.ShowDialog() != DialogResult.OK)
                return;

            var lines= File.ReadAllLines(openFileDialog.FileName);
            var key = GetKey();
            this.dataTextBox.Text = Decrypt(lines, key);
        }
        private void EncryptToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(this.dataTextBox.Text) || string.IsNullOrEmpty(this.encryptionKeyTextBox.Text))
                return;

            var key = GetKey();
            var convertedText = Encrypt(this.dataTextBox.Lines, key, this.addBrTagsCheckBox.Checked);
            this.dataTextBox.Text = convertedText;
        }
        private void DecryptToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(this.dataTextBox.Text)|| string.IsNullOrEmpty(this.encryptionKeyTextBox.Text))
                return;

            var key = GetKey();
            var convertedText=Decrypt(this.dataTextBox.Lines, key);
            this.dataTextBox.Text = convertedText;
        }

        byte[] GetKey() => GetHash(this.encryptionKeyTextBox.Text);
        static byte[] GetHash(string text)
        {
            byte[] result = new byte[128 / 8];

            using (var sha256 = SHA256.Create())
            {
                result = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
            }

            return result;
        }

        static string Encrypt(string[] lines, byte[] key, bool addBrTags)
        {
            StringBuilder sb = null;
            try
            {
                byte[] result = null;

                using (var ms = new MemoryStream())
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;

                    byte[] iv = aes.IV;
                    ms.Write(iv, 0, iv.Length);

                    using (var cryptoStream = new CryptoStream(
                        ms,
                        aes.CreateEncryptor(),
                        CryptoStreamMode.Write))
                    {
                        using (var encryptWriter = new StreamWriter(cryptoStream))
                        {
                            foreach (var line in lines)
                                encryptWriter.WriteLine(line);
                        }
                    }
                    result = ms.ToArray();
                }
                sb = new StringBuilder();
                int i = 0;
                foreach (var b in result)
                {
                    i++;
                    if (i % 25 == 1 & i > 1)
                        sb.Append("\r\n" + (addBrTags ? "<br/>" : ""));
                    sb.Append(b.ToString("x2"));
                }

            }
            catch
            {
                throw;
            }

            if (sb == null)
                return "";
            else
                return sb.ToString();
        }

        static string Decrypt(string[] lines, byte[] key)
        {
            string result = null;
            try
            {
                var ms = new MemoryStream();
                foreach (var line in lines)
                {
                    for (int i = (line.StartsWith("<br/>") ? 5 : 0); i < line.Length; i += 2)
                    {
                        ms.WriteByte(Convert.ToByte(line.Substring(i, 2), 16));
                    }
                }

                ms.Position = 0;

                using (Aes aes = Aes.Create())
                {
                    byte[] iv = new byte[aes.IV.Length];
                    int numBytesToRead = aes.IV.Length;
                    int numBytesRead = 0;
                    while (numBytesToRead > 0)
                    {
                        int n = ms.Read(iv, numBytesRead, numBytesToRead);
                        if (n == 0) break;

                        numBytesRead += n;
                        numBytesToRead -= n;
                    }

                    using (var cryptoStream = new CryptoStream(
                       ms,
                       aes.CreateDecryptor(key, iv),
                       CryptoStreamMode.Read))
                    {
                        using (var decryptReader = new StreamReader(cryptoStream))
                        {
                            string decryptedMessage = decryptReader.ReadToEnd();
                            result = decryptedMessage;
                        }
                    }

                }
            }
            catch
            {
                throw;
            }
            return result ?? "";
        }



    }
}
