import { regularExps } from "../../../config";

export class LoginUserDto {

    private constructor(
        public email: string,
        public password: string,
    ){}

    static login( object: { [key: string]: any } ): [string?, LoginUserDto?]{

        const {email, password} = object;

        if(!email) return ['Missing email'];
        if(!regularExps.email.test(email)) return ['Email is not valid']
        if( password.lenght < 6 ) return ['Password is too short'];



        return [undefined, new LoginUserDto(email, password)];


    }
}