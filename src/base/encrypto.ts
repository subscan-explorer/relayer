import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "crypto";
import { question } from "readline-sync";

export class Encrypto {
  public passwd: string;

  async readPasswd() {
    // get password from env
    if (process.env.HELIX_RELAYER_PASSWORD) {
      this.passwd = createHash('sha256').update(String(process.env.HELIX_RELAYER_PASSWORD)).digest('base64');
      return;
    }
    // exit os print error
    console.error("No password found in env");
    process.exit(1);
  }

  public decrypt(str): string {
    let encrySplit = str.split(":");
    let iv = Buffer.from(encrySplit.shift(), "hex");
    let encrypted = Buffer.from(encrySplit.join(":"), "hex");
    var decipher = createDecipheriv(
      "aes-256-ctr",
      Buffer.from(this.passwd, "base64"),
      iv
    );
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  public encrypt(str): string {
    let iv = randomBytes(16);
    var cipher = createCipheriv(
      "aes-256-ctr",
      Buffer.from(this.passwd, "base64"),
      iv
    );
    let encrypted = cipher.update(str);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString("hex") + ":" + encrypted.toString("hex");
  }
}
