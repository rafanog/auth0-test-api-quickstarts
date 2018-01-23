const chai = require('chai');
const chaiHttp = require('chai-http');
const should = require('chai').should();
require('dotenv').config();

chai.use(chaiHttp);

const apiURL = process.env.API_URL;

const createClientGrant = function(clientId, scopes) {
  const clientGrant = {
    client_id: clientId,
    audience: process.env.AUTH0_AUDIENCE,
    scope: scopes
  }

  return chai.request('https://' + process.env.AUTH0_DOMAIN)
    .post('/api/v2/client-grants')
    .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
    .send(clientGrant);
}

const getToken = function(clientId, clientSecret) {
  tokenRequestBody = {
    'client_id': clientId,
    'client_secret': clientSecret,
    'audience': process.env.AUTH0_AUDIENCE,
    'grant_type': 'client_credentials'
  }

  return chai.request('https://' + process.env.AUTH0_DOMAIN)
    .post('/oauth/token')
    .set('Content-Type', 'application/json')
    .send(tokenRequestBody)
}

const deleteClientGrant = function(clientGrantId) {
  return chai.request('https://' + process.env.AUTH0_DOMAIN)
    .delete('/api/v2/client-grants/' + clientGrantId)
    .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
}

describe('Request without authorization header field', function() {
  it('GET /api/public return 200 OK', function(done) {
    chai.request(apiURL)
    .get('/api/public')
    .end(function(err, res) {
      res.should.have.to.be.json;
      res.should.have.status(200);
      done();
    });
  });

  it('GET /api/private return 401 Unauthorized', function(done) {
    chai.request(apiURL)
    .get('/api/private')
    .end(function(err, res) {
      res.should.have.status(401);
      done();
    });
  });

  it('GET /api/private-scoped return 401 Unauthorized', function(done) {
    chai.request(apiURL)
    .get('/api/private-scoped')
    .end(function(err, res) {
      res.should.have.status(401);
      done();
    });
  });
});

describe('Request with authorization header field', function() {
  let clientId = null;
  let clientSecret = null;

  before(async function() {
    if (!process.env.AUTH0_DOMAIN || !process.env.AUTH0_AUDIENCE || !process.env.AUTH0_MANAGEMENT_API_TOKEN) {
      throw 'Make sure you have AUTH0_DOMAIN, AUTH0_AUDIENCE and AUTH0_MANAGEMENT_API_TOKEN in your .env file'
    }

    const res = await chai.request('https://' + process.env.AUTH0_DOMAIN)
      .post('/api/v2/clients')
      .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
      .send({ name: 'Test API QS Client' })

    clientId = res.body.client_id;
    clientSecret = res.body.client_secret;
    scopes = [
      {
        "description": "Read messages",
        "value": "read:messages"
      },
      {
        "description": "Write messages",
        "value": "write:messages"
      }
    ];
    await chai.request('https://' + process.env.AUTH0_DOMAIN)
      .post('/api/v2/resource-servers')
      .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
      .send({ identifier: process.env.AUTH0_AUDIENCE, scopes: scopes })
  });
      
  after(async function() {
    const res = await chai.request('https://' + process.env.AUTH0_DOMAIN)
      .delete('/api/v2/clients/' + clientId)
      .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)

    await chai.request('https://' + process.env.AUTH0_DOMAIN)
      .delete('/api/v2/resource-servers/' + process.env.AUTH0_AUDIENCE)
      .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
  });

  context('Authorization header field with value \'Bearer \'', function() {
    it('GET /api/private return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });

  context('Authorization header field with value \' \'', function() {
    it('GET /api/private return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', ' ')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', ' ')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });

  context('Authorization header with invalid token', function() {
    it('GET /api/private return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer invalidToken')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer invalidToken')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });

  context('Authorization header field with value \'Bearer invalidToken abc\'', function() {
    it('GET /api/private return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer invalidToken abc')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer invalidToken abc')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });

  context('token with invalid signature', function() {
    let validToken = null;
    let clientGrantId = null;

    before(async function() {
      scope = [];
      const resp = await createClientGrant(clientId, scope);
      clientGrantId = resp.body.id;

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ' + validToken + 'string')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken + 'string')
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });

  context('Valid token without any scope', function() {
    let validToken = null;
    
    before(async function() {
      scope = [];
      const resp = await createClientGrant(clientId, scope);
      clientGrantId = resp.body.id;

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });

    it('GET /api/private-scoped return 403 Insufficent scope', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.status(403);
        done();
      });
    });
  });

  context('Valid token with read:messages scope', function() {
    before(async function() {
      scope = ['read:messages'];
      const resp = await createClientGrant(clientId, scope);
      clientGrantId = resp.body.id;

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });

    it('GET /api/private-scoped return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });
  });

  context('Valid token with write:messages scope', function() {
    before(async function() {
      scope = ['write:messages'];
      const resp = await createClientGrant(clientId, scope);
      clientGrantId = resp.body.id;

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });

    it('GET /api/private-scoped return 403 Insufficent scope', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.status(403);
        done();
      });
    });
  });

  context('Valid token with read:messages and write:messages scopes', function() {
    before(async function() {
      scope = ['read:messages', 'write:messages'];
      const resp = await createClientGrant(clientId, scope);
      clientGrantId = resp.body.id;

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });

    it('GET /api/private-scoped return 200 OK', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.to.be.json;
        res.should.have.status(200);
        done();
      });
    });
  });

  context('Expired token', function() {
    let validToken = null;

    before(async function() {
        scope = ['read:messages'];
        const resp = await createClientGrant(clientId, scope);

        clientGrantId = resp.body.id;

      await chai.request('https://' + process.env.AUTH0_DOMAIN)
        .patch('/api/v2/resource-servers/' + process.env.AUTH0_AUDIENCE)
        .set('Authorization', 'Bearer ' + process.env.AUTH0_MANAGEMENT_API_TOKEN)
        .send({ token_lifetime: 1 })

      const token =  await getToken(clientId, clientSecret);
      validToken = token.body.access_token;
    });

    after(async function() {
      await deleteClientGrant(clientGrantId);
    });

    it('GET /api/private return 401 Unauthorized', function(done) {
      setTimeout(function() {
        chai.request(apiURL)
          .get('/api/private')
          .set('Authorization', 'Bearer ' + validToken)
          .end(function(err, res) {
            res.should.have.status(401);
            done();
          });
      }, 1000);
    });

    it('GET /api/private-scoped return 401 Unauthorized', function(done) {
      chai.request(apiURL)
      .get('/api/private-scoped')
      .set('Authorization', 'Bearer ' + validToken)
      .end(function(err, res) {
        res.should.have.status(401);
        done();
      });
    });
  });
});
