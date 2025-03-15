import pool from '../config/db'

export interface BasicUser {
    email: string,
    password: string
}

export interface User extends BasicUser {
    id: string,
    firstname: string,
    lastname: string,
    isAdmin: boolean
}

export const createUser = async (user: User) => {
    const { id, firstname, lastname, email, password, isAdmin } = user;
    const query = `INSERT INTO users (id, firstname, lastname, email, password, isAdmin) 
    VALUES ($1, $2, $3, $4, $5, $6) 
    RETURNING *`;
    const values = [id, firstname, lastname, email, password, isAdmin]
    const queryResult = await pool.query(query, values);
    return queryResult.rows[0];
}

export const login = async (user: basicUser) => {
    const { email } = user;
    const query = `SELECT * FROM users WHERE email = $1`;
    const values = [email]
    const queryResult = await pool.query(query, values);
    return queryResult.rows[0];
}