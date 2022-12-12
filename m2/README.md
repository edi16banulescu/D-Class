The project aims to achieve the connection between the frontend and the backend of a database. Our middleware server receives and serves HTTP queries. For each query we return a json or an exception.
For User function, we throw an exception for: invalid email, null password, user exists or any other errors. In authUser, we generate a UserAccessToken and return it as a json.
For Url function, we have exception for: empty url. When we search for an url, we serialize it as a json and return it.
For File function, we have exception for: empty file or we return a json with files info.