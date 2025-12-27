import basicAuth from 'basic-auth';

export function basicAuthMiddleware(req, res, next) {
  const user = basicAuth(req);
  const expectedUser = process.env.AUTH_USERNAME;
  const expectedPass = process.env.AUTH_PASSWORD;

  if (!expectedUser || !expectedPass) {
    return res.status(500).json({ error: 'Server auth configuration missing' });
  }

  if (!user || user.name !== expectedUser || user.pass !== expectedPass) {
    res.set('WWW-Authenticate', 'Basic realm="Restricted"');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}



