import { Request, Response, NextFunction } from "express";
import jwt from 'jsonwebtoken';
import { generateAccessToken } from "../utils/generateAccessToken";

interface UserPayload {
    _id: string;
    email: string;
    role: string;
}

declare global {
    namespace Express {
        interface Request {
            user?: UserPayload;
        }
    }
}

export const jwtMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { access_token, refresh_token } = req.cookies;
        console.log("Access token:", access_token);
        console.log("Refresh token:", refresh_token);

        if (!access_token && !refresh_token) {
            return next();
        }

        let user: UserPayload | undefined;

        if (access_token) {
            try {
                user = await jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET!) as UserPayload;
            } catch (error: any) {
                if (error.name !== 'TokenExpiredError') {
                    console.error("Access token verification error:", error);
                    return next(); // Invalid access token
                }
                console.log("Access token expired");
            }
        }

        if (!user && refresh_token) {
            try {
                user = await jwt.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET!) as UserPayload;
                console.log('Refreshed user:', user);

                if (user) {
                    const newAccessToken = generateAccessToken(user);

                    // Create cookie using new access token
                    res.cookie("access_token", newAccessToken, {
                        httpOnly: true,
                    });

                    console.log("New access token generated");
                }
            } catch (error) {
                console.error("Refresh token verification error:", error);
                return next(); // Invalid refresh token
            }
        }

        req.user = user;
        next();
    } catch (error) {
        console.error("Error in JWT middleware:", error);
        next(error); // Call next with error to handle it properly in the middleware chain
    }
};
