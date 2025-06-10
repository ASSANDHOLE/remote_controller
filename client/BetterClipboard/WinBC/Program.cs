namespace WinBC {
    using System;
    using System.Drawing;
    using System.Drawing.Imaging;
    using System.IO;
    using System.Windows.Forms;
    using Newtonsoft.Json;

    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (Clipboard.ContainsImage())
            {
                Image img = Clipboard.GetImage();
                using (MemoryStream ms = new MemoryStream())
                {
                    img.Save(ms, ImageFormat.Png);
                    string base64 = Convert.ToBase64String(ms.ToArray());

                    if (args.Length > 0 && args[0] == "--json")
                    {
                        var json = new { type = "image", data = base64 };
                        Console.WriteLine(JsonConvert.SerializeObject(json));
                    }
                    else
                    {
                        Console.WriteLine(base64);
                    }
                }
            }
            else if (Clipboard.ContainsText())
            {
                string text = Clipboard.GetText();

                if (args.Length > 0 && args[0] == "--json")
                {
                    var json = new { type = "text", data = text };
                    Console.WriteLine(JsonConvert.SerializeObject(json));
                }
                else
                {
                    Console.WriteLine(text);
                }
            }
            else
            {
                Console.Error.WriteLine("Clipboard contains neither image nor text.");
                Environment.Exit(1);
            }
        }
    }    
}