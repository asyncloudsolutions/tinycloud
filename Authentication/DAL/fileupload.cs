using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Data.SqlClient;
using System.Data;
using System.Configuration;
using Authentication.Models;

namespace Authentication.DAL
{
    public class fileupload
    {
        public bool SaveDocument(string filename,byte[] hasheddocument,string sender,string receiver,string ciphertext,string ciphersignature)
        {
            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();
            string strQuery = "insert into digitalfiles(FileName, ContentType, Data,Sender,Receiver,PrivateKey,signature) values (@Name, @ContentType, @Data,@Sender,@Reciever,@PrivateKey,@Signature)";

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@Name", SqlDbType.VarChar).Value = filename;
                    sqlcmd.Parameters.Add("@ContentType", SqlDbType.VarChar).Value = "application / vnd.ms - word";
                    sqlcmd.Parameters.Add("@Data", SqlDbType.Binary).Value = hasheddocument;
                    sqlcmd.Parameters.Add("@Sender", SqlDbType.VarChar).Value = sender;
                    sqlcmd.Parameters.Add("@Reciever", SqlDbType.VarChar).Value = receiver;
                    sqlcmd.Parameters.Add("@PrivateKey", SqlDbType.VarChar).Value = ciphertext;
                    sqlcmd.Parameters.Add("@Signature", SqlDbType.VarChar).Value = ciphersignature;

                    sqlcmd.ExecuteNonQuery();
                }
            }
                return true;
        }

        public DataTable DownloadDocument(string Id)
        {
            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();
            string strQuery ="select FileName, ContentType, Data,privatekey,signature from digitalfiles where id = @id";

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();

                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@id", SqlDbType.Int).Value = Convert.ToInt32(Id);

                    SqlDataAdapter da = new SqlDataAdapter(sqlcmd);
                    DataTable dt=new DataTable();

                    da.Fill(dt);

                    return dt;
                   
                }
            }            
        }

        public List<Models.OrgUsers> ReadAllUserNames()
        {
            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();

            string strQuery = "SELECT ID,USERNAME FROM ASPNetUsers";

            List<OrgUsers> lstUsers = new List<OrgUsers>();
            OrgUsers f;

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;                   

                    SqlDataReader dr = sqlcmd.ExecuteReader();
                    while (dr.Read())
                    {
                        f = new Models.OrgUsers();

                        f.Id= dr["ID"].ToString();
                        f.UserName = dr["USERNAME"].ToString();
                        
                        lstUsers.Add(f);

                    }

                }
            }
            return lstUsers;
        }

        public List<Models.FileInfo> ReadSenderFiles(string userid)
        {
            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();
            
            string strQuery = "SELECT ID,FILENAME,Receiver,senddatetime,privatekey,signature FROM DIGITALFILES Where Sender=@sender";

            List<FileInfo> lstFiles = new List<FileInfo>();
            FileInfo f;

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@sender", SqlDbType.VarChar).Value = userid;

                    SqlDataReader dr = sqlcmd.ExecuteReader();
                    while(dr.Read())
                    {
                        f= new Models.FileInfo();

                        f.Id = Convert.ToInt32(dr["Id"]);
                        f.FileName = dr["FileName"].ToString();
                        f.Sender = dr["Receiver"].ToString();
                        f.SendDateTime = dr["senddatetime"].ToString();
                        f.PrivateKey = dr["privatekey"].ToString();
                        f.Signature = dr["signature"].ToString();

                        lstFiles.Add(f);

                    }
                
                }
            }
            return lstFiles;
        }

        public List<Models.FileInfo> ReadReceivedFiles(string userid)
        {
            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();

            string strQuery = "SELECT ID,FILENAME,sender,senddatetime,privatekey,signature FROM DIGITALFILES Where receiver=@receiver";

            List<FileInfo> lstFiles = new List<FileInfo>();
            FileInfo f;

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@receiver", SqlDbType.VarChar).Value = userid;

                    SqlDataReader dr = sqlcmd.ExecuteReader();
                    while (dr.Read())
                    {
                        f = new Models.FileInfo();

                        f.Id = Convert.ToInt32(dr["Id"]);
                        f.FileName = dr["FileName"].ToString();
                        f.Sender = dr["sender"].ToString();
                        f.SendDateTime = dr["senddatetime"].ToString();
                        f.PrivateKey = dr["privatekey"].ToString();
                        f.Signature = dr["signature"].ToString();
                        f.Message = dr["privatekey"].ToString();

                        lstFiles.Add(f);

                    }

                }
            }
            return lstFiles;
        }

        public bool IsUserNameExists(string username)
        {
            bool isUserExists = false;

            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();

            string strQuery = "SELECT username FROM AspNetUsers Where UserName=@username";
           
            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@username", SqlDbType.VarChar).Value = username.Trim();

                    int rows=sqlcmd.ExecuteNonQuery();
                    if(rows>0)
                    {
                        isUserExists = true;
                    }

                }
            }
            return isUserExists;
        }

        public bool UpdateUserName(string code,string username)
        {
            bool isUserExists = false;

            string constring = ConfigurationManager.ConnectionStrings["DefaultConnection"].ToString();

            string strQuery = "UPDATE AspNetUsers SET UserName=@username Where Id=@code";

            using (SqlConnection sqlcon = new SqlConnection(constring))
            {
                sqlcon.Open();
                using (SqlCommand sqlcmd = new SqlCommand(strQuery, sqlcon))
                {
                    sqlcmd.CommandType = System.Data.CommandType.Text;

                    sqlcmd.Parameters.Add("@username", SqlDbType.VarChar).Value = username;
                    sqlcmd.Parameters.Add("@code", SqlDbType.VarChar).Value = code;

                    int rows = sqlcmd.ExecuteNonQuery();
                    if (rows > 0)
                    {
                        isUserExists = true;
                    }

                }
            }
            return isUserExists;
        }

    }
}