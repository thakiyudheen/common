import { Request, Response, NextFunction } from "express";

// Role-based authorization middleware
export const roleMiddleware = (requiredRole: string) => {
    return (req: Request, res: Response, next: NextFunction): any => {
        const user = req.user;

        if (!user) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        if (user.role !== requiredRole) {
            return res.status(403).json({ message: 'Forbidden' });
        }

        next();
    };
};