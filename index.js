import express from 'express';
import pg from 'pg';
import cookieParser from 'cookie-parser';

// Initialise DB connection
const { Pool } = pg;
const pgConnectionConfigs = {
  user: 'chuanxin',
  host: 'localhost',
  database: 'chuanxin',
  port: 5432, // Postgres server always runs on this port by default
};
const pool = new Pool(pgConnectionConfigs);

const app = express();
// Set view engine
app.set('view engine', 'ejs');
// To receive POST request body data in request.body
app.use(express.urlencoded({ extended: false }));
// To parse cookie string value in the header into a JavaScript Object
app.use(cookieParser());

app.get('/note', (request, response) => {
  response.render('note', {});
});

app.listen(3004);
