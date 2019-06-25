using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Authentication.Models
{
    public class OrgUsers
    {
        public string Id { get; set; }
        public string UserName { get; set; }
    }

    public class FileInfo
    {
        public int Id { get; set; }
        public string FileName { get; set; }
        public string Sender { get; set; }
        public string SendDateTime { get; set; }
        public string PrivateKey { get; set; }
        public string Signature { get; set; }
        public string Message { get; set; }
    }
}