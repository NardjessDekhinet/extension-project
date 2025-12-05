const request = require('supertest');
const app = require('../server'); // make sure server.js exports the app

describe('GET /', () => {
  it('responds with JSON message', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBeDefined();
  });
});
