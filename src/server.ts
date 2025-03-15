import express from "express";
import cookie from "cookie-parser";
import Routes from "./routes/Routes"

const app = express();
app.use(express.json());
app.use(cookie());
app.use("/api", Routes);

const port = 3006;
app.listen(port, () => console.log(`server running on ${port}`))