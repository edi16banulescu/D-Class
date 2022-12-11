import std.algorithm.searching;
import std.conv;
import std.digest;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;
import std.typecons;

import vibe.db.mongo.mongo : connectMongoDB, MongoClient, MongoCollection;
import vibe.data.bson;

import dauth : makeHash, toPassword, parseHash;

struct DBConnection
{
    
    MongoClient client;
    MongoCollection users;
    
    enum UserRet
    {
        OK,
        ERR_NULL_PASS,
        ERR_USER_EXISTS,
        ERR_INVALID_EMAIL,
        ERR_WRONG_USER,
        ERR_WRONG_PASS,
        NOT_IMPLEMENTED
    }

    this(string dbUser, string dbPassword, string dbAddr, string dbPort, string dbName)
    {
        // DONE
        auto connection = "mongodb://" ~ dbUser ~ ":" ~ dbPassword ~ "@" ~ dbAddr ~ ":" ~ dbPort ~ "/";
        auto collection = dbName ~ ".users";
        client = connectMongoDB(connection);
        users = client.getCollection(collection);
    }

    UserRet addUser(string email, string username, string password, string name = "", string desc = "")
    {
        // DONE

        if(password.length < 1) {
            return UserRet.ERR_NULL_PASS;
        }

        if(indexOf(email, "@") == -1)
            return UserRet.ERR_INVALID_EMAIL;

        auto resultOne = users.findOne(["email": email, "username": username, "password": password]);
        if(resultOne != Bson(null)) {
            return UserRet.ERR_USER_EXISTS;
        }
        else {
            users.insert(["email": email, "username": username, "password": password, "name": name, "desc": desc]);
            return UserRet.OK;
        }

    }

    UserRet authUser(string email, string password)
    {
        // DONE

        if(indexOf(email, "@") == -1)
            return UserRet.ERR_INVALID_EMAIL;

        if(password.length < 1) {
            return UserRet.ERR_NULL_PASS;
        }

        auto resultOne = users.findOne(["email": email]);
        if(resultOne != Bson(null)) {
            string thePass = resultOne["password"].get!string;
            if(thePass == password)
                return UserRet.OK;
            else 
                return UserRet.ERR_WRONG_PASS;
        }

        return UserRet.NOT_IMPLEMENTED;
    }

    UserRet deleteUser(string email)
    {
        // DONE
        auto resultOne = users.findOne(["email": email]);
        if(resultOne != Bson(null)) {
            users.remove(["email": email]);
            return UserRet.OK;
        }

        return UserRet.NOT_IMPLEMENTED;
    }

    struct File
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        ubyte[] binData;
        string fileName;
        string digest;
        string securityLevel;
    }

    enum FileRet
    {
        OK,
        FILE_EXISTS,
        ERR_EMPTY_FILE,
        NOT_IMPLEMENTED
    }

    FileRet addFile(string userId, immutable ubyte[] binData, string fileName)
    {
        if(binData == null)
            return FileRet.ERR_EMPTY_FILE;
            
        auto resultOne = users.findOne(["userId": userId, "fileName": fileName]);
        if(resultOne != Bson(null)) {
            return FileRet.FILE_EXISTS;
        }
        else {
            auto dataDigest = digest!SHA512(binData[]).toHexString().to!string;
            users.insert(["userId": userId, "fileName": fileName, "digest": dataDigest,
                             "binData": binData[].to!string]);
            return FileRet.OK;
        }
    }

    File[] getFiles(string userId)
    {
        // not ok
        File[] f;
        auto result = users.find(["userId": userId]);
        auto count = result.count();
        f = new File[count];
        if(!result.empty) {
            int i = 0;
            foreach (r; result)
            {
                // TODO : add ubyte binData
                f[i].userId = r["userId"].to!string;
                f[i].fileName = r["fileName"].to!string;
                f[i].digest = r["digest"].to!string;
                f[i].securityLevel = r["securityLevel"].to!string;
                //f[i].binData[] = r["binData"];
                i++; 
            }
        }
        return f;
    }

    Nullable!File getFile(string digest)
    in(!digest.empty)
    do
    {
        // add BinData
        File file;

        auto resultOne = users.findOne(["digest": digest]);
        if(resultOne != Bson(null)) {
            file.userId = resultOne["userId"].to!string;
            file.fileName = resultOne["fileName"].to!string;
            file.digest = resultOne["digest"].to!string;
            file.securityLevel = resultOne["securityLevel"].to!string;
            //auto tst = resultOne["binData"].to!string;
            //writeln(tst);
            //auto buff = tst.to!ubyte;
            //file.binData[] = resultOne["binData"].to!string.to!ubyte;
            return Nullable!File(file);
        }
        else {
            Nullable!File f;
            return f;
        }
    }

    void deleteFile(string digest)
    in(!digest.empty)
    do
    {
        // DONE
        users.remove(["digest": digest]);
    }

    struct Url
    {
        @name("_id") BsonObjectID id; // represented as _id in the db
        string userId;
        string addr;
        string securityLevel;
        string[] aliases;
    }

    enum UrlRet
    {
        OK,
        URL_EXISTS,
        ERR_EMPTY_URL,
        NOT_IMPLEMENTED
    }

    UrlRet addUrl(string userId, string urlAddress)
    {
        // DONE
        if(urlAddress.length < 1)
            return UrlRet.ERR_EMPTY_URL;

        auto resultOne = users.findOne(["userId": userId, "addr": urlAddress]);
        if(resultOne != Bson(null)) {
            return UrlRet.URL_EXISTS;
        }
        else {
            users.insert(["userId": userId, "addr": urlAddress]);
            return UrlRet.OK;
        }
    }

    Url[] getUrls(string userId)
    {
        // DONE
        Url[] u;
        auto result = users.find(["userId": userId]);
        auto count = result.count();
        u = new Url[count];
        if(!result.empty) {
            int i = 0;
            foreach (r; result)
            {
                u[i].userId = r["userId"].to!string;
                u[i].addr = r["addr"].to!string;
                u[i].securityLevel = r["securityLevel"].to!string;
                u[i].aliases[] = r["aliases"].to!string;
                i++;
            }
        }
        return u;
    }

    Nullable!Url getUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        // DONE
        Url url;
        auto resultOne = users.findOne(["addr": urlAddress]);
        if(resultOne != Bson(null)) {
            url.userId = resultOne["userId"].to!string;
            url.addr = resultOne["addr"].to!string;
            url.securityLevel = resultOne["securityLevel"].to!string;
            url.aliases[] = resultOne["aliases"].to!string;
            return Nullable!Url(url);
        }
        else {
            Nullable!Url u;
            return u;
        }
    }

    void deleteUrl(string urlAddress)
    in(!urlAddress.empty)
    do
    {
        //DONE
        users.remove(["addr": urlAddress]);
    }
}
