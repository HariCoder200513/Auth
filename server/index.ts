import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config } from './config';
import { attachUser } from './session';
import { router } from './routes';

const app = express();

app.use(
  cors({
    origin: config.clientOrigin,
    credentials: true
  })
);
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(attachUser);
app.use('/api', router);

app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  const message = error instanceof Error ? error.message : 'Unexpected server error';
  console.error(error);
  response.status(500).json({ error: message });
});

app.listen(config.port, () => {
  console.log(`Z-Auth API listening on http://localhost:${config.port}`);
});
