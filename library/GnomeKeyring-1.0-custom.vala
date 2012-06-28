namespace GnomeKeyring {
	[Compact]
	public class AttributeList : GLib.Array<GnomeKeyring.Attribute> {
		[CCode (array_length_cname = "len", array_length_type = "guint")]
		public GnomeKeyring.Attribute[] data;
		public void append_string (string name, string value);
		public void append_uint32 (string name, uint32 value);
		public GnomeKeyring.AttributeList copy ();
		public AttributeList ();
	}

	[CCode (cheader_filename = "gnome-keyring.h", free_function = "gnome_keyring_network_password_free")]
	[Compact]
	public class NetworkPasswordData { }

	[CCode (cheader_filename = "gnome-keyring.h")]
	public delegate void OperationGetListCallback<T> (GnomeKeyring.Result result, GLib.List<T> list);
	[CCode (cheader_filename = "gnome-keyring.h")]
	public static GnomeKeyring.PasswordSchema NETWORK_PASSWORD;
	[CCode (cheader_filename = "gnome-keyring.h")]
	public const string DEFAULT;
	[CCode (cheader_filename = "gnome-keyring.h")]
	public static unowned string result_to_message (GnomeKeyring.Result res);
}