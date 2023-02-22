import vibe.vibe;
import virus_total;
import db_conn;

import std.stdio;

void main()
{

    auto dbClient = DBConnection("root", "example", "mongo", "27017", "testing");
    auto virusTotalAPI = new VirusTotalAPI(dbClient);

    auto router = new URLRouter;
    router.registerRestInterface(virusTotalAPI);

    router.get("*", serveStaticFiles("public/"));
    router.get("/", &hello);
    router.get("/login", &loginPage);
    router.get("/signup", &signupPage);
    router.get("/delete_user", &deleteUserPage);
    router.get("/home", &homePage);
    router.get("/home/file", &filePage);
    router.get("/home/file/add_file", &add_file);
    router.get("/home/file/file_info", &fileInfoPage);
    router.get("/home/file/user_files", &userFilesPage);
    router.get("/home/file/delete_file", &deleteFilePage);
    router.get("/home/url", &urlPage);
    router.get("/home/url/add_url", &add_url);
    router.get("/home/url/url_info", &urlInfo);
    router.get("/home/url/user_urls", &userUrlsPage);
    router.get("/home/url/delete_url", &deleteUrlPage);

    auto settings = new HTTPServerSettings;
    settings.port = 8080;
    settings.bindAddresses = ["0.0.0.0"];
    auto listener = listenHTTP(settings, router);
    scope (exit)
    {
        listener.stopListening();
    }

    logInfo("Please open http://localhost:8080/ in your browser.");
    runApplication();

}

void hello(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("landing.dt")(res);
}

void signupPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("signup.dt")(res);
}

void loginPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("login.dt")(res);
}

void deleteUserPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("deleteUser.dt")(res);
}

void homePage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("index.dt")(res);
}

void filePage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("file.dt")(res);
}

void urlPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("url.dt")(res);
}

void add_file(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("add_file.dt")(res);
}

void add_url(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("add_url.dt")(res);
}

void fileInfoPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("file_info.dt")(res);
}

void userFilesPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("user_files.dt")(res);
}

void deleteFilePage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("delete_file.dt")(res);
}

void urlInfo(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("url_info.dt")(res);
}

void userUrlsPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("user_urls.dt")(res);
}

void deleteUrlPage(HTTPServerRequest req, HTTPServerResponse res)
{
    render!("delete_url.dt")(res);
}
