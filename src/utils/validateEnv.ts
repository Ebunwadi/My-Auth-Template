import { cleanEnv } from 'envalid'
import { port, str } from 'envalid/dist/validators'

export default cleanEnv(process.env, {
  DATABASE_URI: str(),
  PORT: port(),
  ACCESS_TOKEN_SECRET: str(),
  REFRESH_TOKEN_SECRET: str(),
  JWT_SECRET: str(),
  MAIL_PASSWORD: str(),
  MAIL_USER: str(),
  MAIL_SERVICE: str(),
  BASE_URL: str()
})
