namespace Oogi.Identity
{
    public class Messages
    {
        // username validation messages
        public string UserNameTooShort = "Uživatelské jméno je prázdné.";
        public string InvalidUserName = "Uživatelské jméno {0} může obsahovat pouze písmena a čísla.";
        public string DuplicateName = "Uživatelské jméno {0} již existuje.";

        // e-mail validation messages
        public string EmailTooShort = "E-mail nemůže být prázdný.";
        public string InvalidEmail = "E-mail {0} je neplatný.";
        public string DuplicateEmail = "Uživatel s e-mailem {0} již existuje.";

        // password validation messages
        public string PasswordTooShort = "Zadané heslo je příliš krátké. Minimální délka je {0} znaků.";
        public string PasswordRequireNonLetterOrDigit = "Heslo musí obsahovat speciální znak, co není písmeno ani číslice.";
        public string PasswordRequireDigit = "Heslo musí obsahovat číslici.";
        public string PasswordRequireLower = "Heslo musí obsahovat malé písmeno.";
        public string PasswordRequireUpper = "Heslo musí obsahovat velké písmeno.";
    }
}
