using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;

namespace nexusauth.ChallengeResponse
{
    public class Challenge
    {
        public string challenge;
        public string challenge64;
        public double servertime;

        public Challenge()
        {
            TimeSpan timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0);
            servertime = timeSpan.TotalSeconds;
            challenge = string.Join("", GetRandomBytes(128).Select(x => x.ToString("X2")));
            challenge64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(challenge));
        }

        public byte[] GetRandomBytes(int n)
        {
            byte[] rnd = new byte[n];
            Random rng = new Random();
            rng.NextBytes(rnd);
            return rnd;
        }
    }
}