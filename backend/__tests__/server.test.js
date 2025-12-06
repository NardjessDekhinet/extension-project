const request = require('supertest');
const app = require('../server');
//unit test with jest 
describe('GET /', () => {
  it('responds with JSON message', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('message');
  });
});
