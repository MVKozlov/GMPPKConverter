namespace GMax.Security
{
    public enum Argon2Type
    {
        Argon2i,
        Argon2d,
        Argon2id,
    }
    public class Argon2Params
    {
        public Argon2Type KeyDerivation { get; set; }
        public int Memory { get; set; }
        public int Passes { get; set; }
        public int Parallelism { get; set; }
        public byte[] Salt { get; set; }
    }
}
