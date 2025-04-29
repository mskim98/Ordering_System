import 'express';

declare global {
  namespace Express {
    // Request 객체에 user 속성 추가
    interface Request {
      user?: {
        id: string;
        [key: string]: any;
      };
    }
  }
}
