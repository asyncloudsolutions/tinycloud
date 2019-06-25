using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Authentication.DAL;
using System.Data;
using Authentication.Models;
using System.Security.Cryptography;
using Authentication.Helper;
using static Authentication.Helper.Sender;

namespace Authentication.Controllers
{
    [Authorize]
    public class FileUploadController : Controller
    {
        public ActionResult Index()
        {
            string reciever=string.Empty;
            string privatekey = string.Empty;

            if (Request.Form.Count > 0)
            {
                reciever = Request.Form["Reciever"].ToString();
                privatekey = Request.Form["PrivateKey"].ToString();
            }
            fileupload f = new fileupload();

            foreach (string upload in Request.Files)
            {
                if (Request.Files[upload].FileName != "")
                {
                    string path = AppDomain.CurrentDomain.BaseDirectory + "/App_Data/uploads/";
                    string filename = Path.GetFileName(Request.Files[upload].FileName);
                    Request.Files[upload].SaveAs(Path.Combine(path, filename));
                    
                    FileStream fs = new FileStream(Path.Combine(path, filename), FileMode.Open, FileAccess.Read);

                    BinaryReader br = new BinaryReader(fs);
                    Byte[] bytes = br.ReadBytes((Int32)fs.Length);
                    
                    Sender sender = new Sender();
                    DigitalSignatureResult res = sender.BuildSignedMessage(privatekey);

                    f.SaveDocument(filename, bytes, Session["LoggedInUser"].ToString(), reciever,res.CipherText,res.SignatureText);

                    br.Close();
                    fs.Close();

                }
            }
            
            List<OrgUsers> users = f.ReadAllUserNames();

            ViewBag.OrgUsers = new SelectList(users,"Id","UserName");

            return View("Upload");
        }

        public ActionResult Downloads()
        {
            
            fileupload fobj = new fileupload();
            List<Models.FileInfo> lstFiles= fobj.ReadSenderFiles(Session["LoggedInUser"].ToString());

            DigitalSignatureResult res;
            foreach (Models.FileInfo f in lstFiles)
            {
                res = new DigitalSignatureResult();
                res.CipherText = f.PrivateKey;
                res.SignatureText = f.Signature;

                f.Message = new Receiver().ExtractMessage(res);
                f.PrivateKey = f.PrivateKey.Substring(0, 30);
            }


            return View(lstFiles);

            //return View(items);
        }

        public ActionResult Received()
        {
            fileupload fobj = new fileupload();
            List<Models.FileInfo> lstFiles = fobj.ReadReceivedFiles(Session["LoggedInUser"].ToString());

            DigitalSignatureResult res;
            foreach (Models.FileInfo f in lstFiles)
            {
                res = new DigitalSignatureResult();
                res.CipherText = f.PrivateKey;
                res.SignatureText = f.Signature;

                f.Message = new Receiver().ExtractMessage(res);
                f.PrivateKey = f.PrivateKey.Substring(0, 30);
            }

            return View(lstFiles);

            //return View(items);
        }

        [HttpGet]
        public FileResult Download(string senderid,string senderpublickey)
        {            
            fileupload f = new fileupload();            

            DataTable dt= f.DownloadDocument(senderid);
            if(VerifyDocument(dt))
            {
                Byte[] bytes = download1(dt);
                return File(bytes, "application / force - download",dt.Rows[0]["FileName"].ToString());
            }

            return null;
            
            //var FileVirtualPath = "~/App_Data/uploads/" + ImageName;
            //return File(FileVirtualPath, "application/force-download", Path.GetFileName(FileVirtualPath));

        }

        private bool VerifyDocument(DataTable dt)
        {

            Byte[] bytes = (Byte[])dt.Rows[0]["Data"];

            DigitalSignatureResult res=new DigitalSignatureResult();
            res.CipherText= dt.Rows[0]["privatekey"].ToString();
            res.SignatureText= dt.Rows[0]["signature"].ToString();
            
            string securitycode = new Receiver().ExtractMessage(res);

            if (securitycode != "")
                return true;
            else
                return false;                        
        }

        private Byte[] download1(DataTable dt)

        {
                        
            Byte[] bytes = (Byte[])dt.Rows[0]["Data"];

            //Response.Buffer = true;

            //Response.Charset = "";

            //Response.Cache.SetCacheability(HttpCacheability.NoCache);

            //Response.ContentType = dt.Rows[0]["ContentType"].ToString();

            //Response.AddHeader("content-disposition", "attachment;filename="

            //+ dt.Rows[0]["FileName"].ToString());

            //Response.BinaryWrite(bytes);

            //Response.Flush();

            //Response.End();

            return bytes;
        }
    }
}