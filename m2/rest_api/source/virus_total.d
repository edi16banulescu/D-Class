import std.conv;
import std.digest;
import std.digest.sha;
import std.stdio;

import vibe.d;
import vibe.web.auth;

import db_conn;

static struct AuthInfo
{
@safe:
    string userEmail;
}

@path("api/v1")
@requiresAuth
interface VirusTotalAPIRoot
{
    // Users management
    @noAuth
    @method(HTTPMethod.POST)
    @path("signup")
    Json addUser(string userEmail, string username, string password, string name = "", string desc = "");

    @noAuth
    @method(HTTPMethod.POST)
    @path("login")
    Json authUser(string userEmail, string password);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_user")
    Json deleteUser(string userEmail);

    // URLs management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_url") // the path could also be "/url/add", thus defining the url "namespace" in the URL
    Json addUrl(string userEmail, string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path("url_info")
    Json getUrlInfo(string urlAddress);

    @noAuth
    @method(HTTPMethod.GET)
    @path ("user_urls")
    Json getUserUrls(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_url")
    Json deleteUrl(string userEmail, string urlAddress);

    // Files management
    @anyAuth
    @method(HTTPMethod.POST)
    @path("add_file")
    Json addFile(string userEmail, immutable ubyte[] binData, string fileName);

    @noAuth
    @method(HTTPMethod.GET)
    @path("file_info")
    Json getFileInfo(string fileSHA512Digest);

    @noAuth
    @method(HTTPMethod.GET)
    @path("user_files")
    Json getUserFiles(string userEmail);

    @anyAuth
    @method(HTTPMethod.POST)
    @path("delete_file")
    Json deleteFile(string userEmail, string fileSHA512Digest);
}

class VirusTotalAPI : VirusTotalAPIRoot
{
    this(DBConnection dbClient)
    {
        this.dbClient = dbClient;
    }

    @noRoute AuthInfo authenticate(scope HTTPServerRequest req, scope HTTPServerResponse res)
    {
        // If "userEmail" is not present, an error 500 (ISE) will be returned
        string userEmail = req.json["userEmail"].get!string;
        string userAccessToken = dbClient.getUserAccessToken(userEmail);
        // Use headers.get to check if key exists
        string headerAccessToken = req.headers.get("AccessToken");
        if (headerAccessToken && headerAccessToken == userAccessToken)
            return AuthInfo(userEmail);
        throw new HTTPStatusException(HTTPStatus.unauthorized);
    }

override:


    Json addUser(string userEmail, string username, string password, string name = "", string desc = "")
    {
        // DONE
       if(password.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "null pass");
       }

       if(indexOf(userEmail, "@") == -1) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "wrong email");
       }

        auto res = dbClient.getUserData(userEmail);
        if(res != Bson(null)) {
            throw new HTTPStatusException(HTTPStatus.unauthorized, "existing user");
        } else {
            dbClient.addUser(userEmail, username, password, name, desc);
        }
        Json json;
        return json;
    }

    Json authUser(string userEmail, string password)
    {
        // DONE
        if(password.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "null pass");
        }

       if(indexOf(userEmail, "@") == -1) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "wrong email");
       }

       if(dbClient.authUser(userEmail, password) == DBConnection.UserRet.ERR_WRONG_PASS ||
                    dbClient.authUser(userEmail, password) == DBConnection.UserRet.ERR_WRONG_USER) { 
            throw new HTTPStatusException(HTTPStatus.unauthorized, "wrong credentials");
       } else {
            auto AccessToken = dbClient.generateUserAccessToken(userEmail);

            auto json = serializeToJson(["AccessToken": AccessToken]);
            return json;
       }
    }

    Json deleteUser(string userEmail)
    {
        // DONE
        if(indexOf(userEmail, "@") == -1) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "wrong email");
        } else {
            dbClient.deleteUser(userEmail); 
            auto AccessToken = dbClient.getUserAccessToken(userEmail);
            Json json = serializeToJson(["AccesToken": AccessToken]);
            return json;
            }
    }

    // URLs management

    Json addUrl(string userEmail, string urlAddress)
    {
        // DONE
        if(urlAddress.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty url");
        } else {
            dbClient.addUrl(userEmail, urlAddress);
            auto AccessToken = dbClient.getUserAccessToken(userEmail);
            Json json = serializeToJson(["AccesToken" : AccessToken]);
            return json;
        }
    }

    Json deleteUrl(string userEmail, string urlAddress)
    {
        // DONE
        if(urlAddress.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty url");
        } else {
            dbClient.deleteUrl(userEmail, urlAddress);
            auto AccessToken = dbClient.getUserAccessToken(userEmail);
            Json json = serializeToJson(["AccesToken" : AccessToken]);
            return json;
        }
    }

    Json getUrlInfo(string urlAddress)
    {
        // DONE
        if(dbClient.getUrl(urlAddress).isNull) {
            throw new HTTPStatusException(HTTPStatus.notFound, "notFound");
        } else {
            auto myUrl = dbClient.getUrl(urlAddress);
            Json json = myUrl.serializeToJson();
            return json;
        }
    }

    Json getUserUrls(string userEmail)
    {
        // DONE
        Json json;
        auto myUrls = dbClient.getUrls(userEmail);
        json = myUrls.serializeToJson();
        return json;
    }

    // Files management

    Json addFile(string userEmail, immutable ubyte[] binData, string fileName)
    {
        // DONE
        if(binData.empty) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty");
        }
        dbClient.addFile(userEmail, binData, fileName);
        
        auto AccessToken = dbClient.getUserAccessToken(userEmail);
        Json json = serializeToJson(["AccesToken" : AccessToken]);
        return json;
    }

    Json getFileInfo(string fileSHA512Digest)
    {
        // DONE
        if(dbClient.getFile(fileSHA512Digest).isNull) {
            throw new HTTPStatusException(HTTPStatus.notFound, "notFound");
        } else {
            auto myFile = dbClient.getFile(fileSHA512Digest);
            Json json = myFile.serializeToJson();
            return json;
        }
    }

    Json getUserFiles(string userEmail)
    {
        // DONE
        auto myFiles = dbClient.getFiles(userEmail);
        Json json = myFiles.serializeToJson();
        return json;
    }

    Json deleteFile(string userEmail, string fileSHA512Digest)
    {
        // DONE
        if(fileSHA512Digest.length == 0) {
            throw new HTTPStatusException(HTTPStatus.badRequest, "empty file");
        } else {
            dbClient.deleteFile(userEmail, fileSHA512Digest);
            auto AccessToken = dbClient.getUserAccessToken(userEmail);
            Json json = serializeToJson(["AccesToken" : AccessToken]);
            return json;
        }
    }

private:
    DBConnection dbClient;
}
