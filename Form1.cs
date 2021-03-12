/// Oğulcan Topsakal
/// Last update 05.01.2021


using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace OTSteganography
{
    public partial class Form1 : Form
    {
        #region Variables

        //Control var for embed/extract algorithmn
        private enum State
        {
            Write,
            Stop,
            Read
        };

        private int imWidth             = 0;        //loaded image's width(px)
        private int imHeight            = 0;        //loaded image's height(px)
        private bool dumb               = false;    //wrong passcode|key flag
        private bool isImgLoaded        = false;    //image loading flag
        private string decryptionKey    = "";       //decryption key

        #endregion

        public Form1()
        {
            InitializeComponent();
        }

        #region UI

        /// <summary>
        /// Runs only at first frame.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Form1_Load(object sender, EventArgs e)
        {
            comboBox1.Items.Add(1);
            comboBox1.Items.Add(2);
            comboBox1.Items.Add(3);
            comboBox1.Items.Add(4);
            comboBox1.Items.Add(5);
            comboBox1.Items.Add(7);
            comboBox1.Items.Add(10);
            comboBox1.Items.Add(11);
            comboBox1.Items.Add(12);
            comboBox1.Items.Add(13);
            comboBox1.Items.Add(14);
            comboBox1.Items.Add(15);
            comboBox1.Items.Add(16);
            comboBox1.Items.Add(17);
            comboBox1.Items.Add(18);
            comboBox1.Items.Add(19);
            comboBox1.Items.Add(20);
            comboBox1.Items.Add(21);
            comboBox1.Items.Add(22);
            comboBox1.Items.Add(23);
            comboBox1.Items.Add(24);
            comboBox1.Items.Add(25);
            comboBox1.SelectedIndex = 0;
        }

        /// <summary>
        /// Runs at every time message text box changes. It controls embed button's state.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void textBox1_TextChanged(object sender, EventArgs e)
        {
            if (textBox1.Text.Length <= 0 || !isImgLoaded || textBox3.Text.Length<=0)
            {
                buttonEmbeddText.Enabled = false;
            }
            else
            {
                buttonEmbeddText.Enabled = true;
            }
        }

        /// <summary>
        /// Runs at every time pass code text box changes. It controls embed button's state.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void textBox3_TextChanged(object sender, EventArgs e)
        {
            if (textBox1.Text.Length <= 0 || !isImgLoaded || textBox3.Text.Length <= 0)
            {
                buttonEmbeddText.Enabled = false;
            }
            else
            {
                buttonEmbeddText.Enabled = true;
            }
        }

        /// <summary>
        /// Extract button click event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonExtractText_Click(object sender, EventArgs e)
        {
            ExtractMessage();
        }

        /// <summary>
        /// Embed button click event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void buttonEmbeddText_Click(object sender, EventArgs e)
        {
            EmbeddMessage(textBox1.Text, new Bitmap(pictureBox1.Image));
        }

        /// <summary>
        /// Load Image button click event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ButtonLoadImage_Click(object sender, EventArgs e)
        {
            OpenFileDialog open = new OpenFileDialog();
            open.Filter = "Image Files(*.jpg; *.jpeg; *.gif; *.png; *.bmp)|*.jpg; *.jpeg; *.gif; *.png; *.bmp";
            if (open.ShowDialog() == DialogResult.OK)
            {
                pictureBox1.Image = new Bitmap(open.FileName);
                
                //To inform user show some specs on screen
                label2.Text = "Width: " + pictureBox1.Image.Size.Width + "\n"
                            + "Height: " + pictureBox1.Image.Size.Height + "\n"
                            + "Usable text length: "+ (((pictureBox1.Image.Size.Width * pictureBox1.Image.Size.Height) / 3) * 9 / 10).ToString();

                //Store these to use later
                imWidth = pictureBox1.Image.Size.Width;
                imHeight = pictureBox1.Image.Size.Height;

                //UI shenanigans
                isImgLoaded = true;
                buttonExtractText.Enabled = true;
                buttonExtractText.BackColor = Color.FromArgb(239, 35, 60);
                if (textBox1.Text.Length > 0)
                {
                    buttonEmbeddText.BackColor = Color.FromArgb(239, 35, 60);
                    buttonEmbeddText.Enabled = true;
                }
            }
        }

        #endregion

        #region Steganography

        /// <summary>
        /// Extraction algorithm.
        /// </summary>
        /// <param name="decrypt">Decryption key</param>
        private void ExtractMessage()
        {
            if(textBox2.Text == "" || textBox2.Text == " " || textBox3.Text == "" || textBox3.Text == " ")
            {
                MessageBox.Show("Please fill both of key and pass code.#ERR");
            }
            else
            {
                
                string decrypt = Decrypt(textBox2.Text, textBox3.Text);
                if(decrypt == null || decrypt == "" || dumb)
                {
                    MessageBox.Show("Hidden message: You dumb!");
                    dumb = false;
                }
                else
                {
                    string[] pos = decrypt.Split(' ');

                    State state = State.Stop;

                    int colorUnitIndex = 0;
                    string extractedText = String.Empty;
                    Bitmap bmap = new Bitmap(pictureBox1.Image);

                    for (int i = 0; i < bmap.Height; i++)
                    {
                        for (int j = 0; j < bmap.Width; j++)
                        {
                            Color pixel = bmap.GetPixel(j, i);

                            //Check current state
                            if (int.Parse(pos[0]) == j && int.Parse(pos[1]) == i)
                                state = State.Read;

                            //do read if start pos passed
                            if (state == State.Read)
                            {
                                for (int n = 0; n < 3; n++)
                                {
                                    switch (colorUnitIndex % 3)
                                    {
                                        case 0:
                                            {

                                                extractedText += (pixel.R % 2).ToString();
                                            }
                                            break;
                                        case 1:
                                            {
                                                extractedText += (pixel.G % 2).ToString();
                                            }
                                            break;
                                        case 2:
                                            {
                                                extractedText += (pixel.B % 2).ToString();
                                            }
                                            break;
                                    }
                                    colorUnitIndex++;
                                    if (colorUnitIndex % 8 == 0)
                                    {
                                        extractedText += " ";
                                    }
                                }
                            }

                            //abort reading
                            if (int.Parse(pos[2]) == j && int.Parse(pos[3]) == i)
                                state = State.Stop;
                        }
                    }
                    string hiddenMessage = "";
                    string[] message = extractedText.Split(' ');
                    for (int i = 0; i < message.Length; i++)
                    {
                        if (message[i].Length > 7)
                            hiddenMessage += BinaryToString(message[i]);
                    }
                    string cb = comboBox1.GetItemText(comboBox1.SelectedItem);
                    MessageBox.Show("Hidden Message: " +  Decipher(hiddenMessage, int.Parse(cb)));
                }
                
            }

        }
       
        /// <summary>
        /// This func calls techniques to hide data.
        /// PS: We are seperating this func to use with other techniques aswell.
        /// </summary>
        /// <param name="msg">Text which wants to be hidden</param>
        /// <param name="bmap">Bitmap of image</param>
        private void EmbeddMessage(string msg, Bitmap bmap)
        {
            string binStr = "";
            string cb = comboBox1.GetItemText(comboBox1.SelectedItem);
            byte[] byteArr = Encoding.ASCII.GetBytes(Encipher(msg, int.Parse(cb)));
            binStr += "";
            for (int i = 0; i < byteArr.Length; i++)
            {
                binStr += Convert.ToString(byteArr[i], 2).PadLeft(8, '0');
            }

            int totalPixelNeeded;
            if (binStr.Length % 3 != 0)
            {
                totalPixelNeeded = (binStr.Length / 3) + 1;
            }
            else
            {
                totalPixelNeeded = (binStr.Length / 3);
            }

            LRWriter(totalPixelNeeded, bmap, binStr);
        }

       
        /// <summary>
        /// This func embedd data to image (left to right).
        /// </summary>
        /// <param name="totalPixel">Total needed pixel to store data</param>
        /// <param name="bmap">Bitmap of image</param>
        /// <param name="bin">Converted binary string of embedding data</param>
        private void LRWriter(int totalPixel, Bitmap bmap, string bin)
        {
            State state = State.Stop;
            string holder = "";
            //To fit data control bounds of random pos
            int maxPixel = (bmap.Height * bmap.Width) - 1;
            maxPixel -= totalPixel;

            //Generate random start position
            int[] sPos = PickStartPos(bmap, maxPixel);
            decryptionKey += sPos[0].ToString()+ " " + sPos[1].ToString() + " ";

            int countdown = 0;//Counting while putting data
            int binIndex = 0;//Index of processed bin str

            for (int i = 0; i < imHeight; i++)
            {
                for (int j = 0; j < imWidth; j++)
                {
                    //Seperate pixel to color channels
                    Color pixel = bmap.GetPixel(j, i);
                    int nR = pixel.R;
                    int nG = pixel.G;
                    int nB = pixel.B;

                    //Check if we hit start pos
                    if(sPos[0] == j && sPos[1] == i)
                    {
                        state = State.Write;
                    }

                    if (state == State.Stop)
                    {
                        bmap.SetPixel(j, i, Color.FromArgb(nR, nG, nB));
                    }
                    else if(state == State.Write)//put binary data inside color channel's lsbs
                    {
                        for (int n = 0; n < 3; n++)
                        {
                            if (n % 3 == 0)
                            {
                                if (binIndex < bin.Length)
                                {
                                    if (bin[binIndex] == '0')
                                    {
                                        nR = pixel.R & ~1;
                                    }
                                    else
                                    {
                                        nR = pixel.R | 1;
                                    }
                                    holder += (nR % 2).ToString();
                                }                         
                            }
                            else if (n % 3 == 1)
                            {
                                if (binIndex < bin.Length)
                                {
                                    if (bin[binIndex] == '0')
                                    {
                                        nG = pixel.G & ~1;
                                    }
                                    else
                                    {
                                        nG = pixel.G | 1;
                                    }
                                    holder += (nG % 2).ToString();
                                }                      
                            }
                            else if (n % 3 == 2)
                            {
                                if(binIndex < bin.Length)
                                {
                                    if (bin[binIndex] == '0')
                                    {
                                        nB = pixel.B & ~1;
                                    }
                                    else
                                    {
                                        nB = pixel.B | 1;
                                    }
                                    holder += (nB % 2).ToString();
                                }
                            }
                            binIndex++;
                        }

                        bmap.SetPixel(j, i, Color.FromArgb(nR, nG, nB));
                        countdown++;

                        if (countdown >= totalPixel)
                        {
                            decryptionKey += j.ToString() + " " + i.ToString();
                            state = State.Stop;
                        }
                    }
                    
                }
            }
            
            //No data loss while saving png #Saving part
            SaveFileDialog dialog = new SaveFileDialog();

            MessageBox.Show("Choose image to hide your message.",
                "Image Save",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning 
               );
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                bmap.Save(dialog.FileName, ImageFormat.Png);
            }

            string sout = "Key: " + Encrypt(decryptionKey, textBox3.Text) + "\nPass Code: " + textBox3.Text+"\nCaesar Cipher Key: "+comboBox1.SelectedItem.ToString();
            MessageBox.Show("Choose text file to write key&passcode.",
                "Text Save",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning
               );
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                File.WriteAllText(dialog.FileName, sout);
            }

            //Clean ui
            textBox1.Text = "";
            textBox2.Text = "";
            textBox3.Text = "";
            decryptionKey = "";
        }

        #endregion

        #region Helper Methods
        /// <summary>
        /// It converts binary text data as string.
        /// </summary>
        /// <param name="data">Binary string</param>
        /// <returns>string</returns>
        public static string BinaryToString(string data)
        {
            List<Byte> byteList = new List<Byte>();

            for (int i = 0; i < data.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(data.Substring(i, 8), 2));
            }
            return Encoding.ASCII.GetString(byteList.ToArray());
        }

        

        /// <summary>
        /// It generates random start position to hidden data with knowledge data length and total space.
        /// </summary>
        /// <param name="bmap">Used bitmap for data embedding</param>
        /// <param name="totalSpace">Total choosable number space</param>
        /// <returns></returns>
        private int[] PickStartPos(Bitmap bmap, int totalSpace)
        {
            Random rand = new Random();
            //We are using 3 pixel to fit our start and stop position info
            int startPos = rand.Next(4, totalSpace - 4);
            int[] cord = new int[2];

            //Calc (x,y) of start pos
            cord[0] = startPos % bmap.Width;
            cord[1] = startPos / bmap.Width;

            return cord;
        }
        #endregion

        #region Crytography

        private const int Keysize = 256;
        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            try
            {
                var cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
                // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
                var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
                // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
                var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
                // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
                var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

                using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
                {
                    var keyBytes = password.GetBytes(Keysize / 8);
                    using (var symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.BlockSize = 256;
                        symmetricKey.Mode = CipherMode.CBC;
                        symmetricKey.Padding = PaddingMode.PKCS7;
                        using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                        {
                            using (var memoryStream = new MemoryStream(cipherTextBytes))
                            {
                                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                                {
                                    var plainTextBytes = new byte[cipherTextBytes.Length];
                                    var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                    memoryStream.Close();
                                    cryptoStream.Close();
                                    return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                dumb = true;
                return null;
            }
            
        }   

        private byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        #region Caesar Cipher

        public char Cipher(char ch, int key)
        {
            if (!char.IsLetter(ch))
            {

                return ch;
            }

            char d = char.IsUpper(ch) ? 'A' : 'a';
            return (char)((((ch + key) - d) % 26) + d);


        }

        public string Encipher(string input, int key)
        {
            string output = string.Empty;

            foreach (char ch in input)
                output += Cipher(ch, key);

            return output;
        }

        public string Decipher(string input, int key)
        {
            return Encipher(input, 26 - key);
        }

        #endregion

        #endregion

    }

}
