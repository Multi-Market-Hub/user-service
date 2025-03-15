import { z } from 'zod';

const userSchema = z.object({
    firstname: z.string().min(2, "Name must be 2 characters long"),
    lastname: z.string(),
    email: z.string().email("Invalid Email Format"),
    password: z.string(),
    isAdmin: z.boolean().optional(),
});
export default userSchema;