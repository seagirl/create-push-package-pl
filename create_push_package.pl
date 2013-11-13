#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use Archive::Zip qw(:ERROR_CODES :CONSTANTS);
use Crypt::SMIME;
use Data::Dumper;
use Digest::SHA qw(sha1_hex);
use File::Copy qw/copy/;
use File::Path qw/make_path/;
use JSON;
use MIME::Base64;
use OpenCA::OpenSSL;
use OpenCA::OpenSSL::SMIME;
use OpenCA::X509;
use Path::Tiny;

my $certificate_path = "create_push_package/cert.pem";
my $private_key_path = "create_push_package/private_key.pem";
my @raw_files = (
	'icon.iconset/icon_16x16.png',
	'icon.iconset/icon_16x16@2x.png',
	'icon.iconset/icon_32x32.png',
	'icon.iconset/icon_32x32@2x.png',
	'icon.iconset/icon_128x128.png',
	'icon.iconset/icon_128x128@2x.png',
	'website.json',
);

sub copy_raw_push_package_files {
	my ($dst) = @_;
	for my $file (@raw_files) {
		make_path(path("$dst/$file")->dirname, { mode => 0775 });
		copy("create_push_package/$file", "$dst/$file")
			or die "Can't copy create_push_package/$file to $dst/$file: " . $!;
	}
}

sub create_manifest {
	my ($dst) = @_;

	my $data;
	for my $file (@raw_files) {
		$data->{$file} = sha1_hex(path("$dst/$file")->slurp);
	}

	my $json = JSON->new;
	$json->pretty(1);
	$json->ascii;

	path("$dst/manifest.json")->spew($json->encode($data));
}

sub create_signature {
	my ($dst, $cert_path, $key_path) = @_;

	my $cert = path("$cert_path")->slurp;
	my $key = path("$key_path")->slurp;

	my $plain = path("$dst/manifest.json")->slurp;

	my $shell = OpenCA::OpenSSL->new;
	my $x509 = OpenCA::X509->new(
		DATA  => $cert,
		SHELL => $shell,
	);
	my $smime = OpenCA::OpenSSL::SMIME->new(
		DATA  => $plain,
		SHELL => $shell,
	);

	$smime->sign(
		CERTIFICATE => $x509,
		PRIVATE_KEY => $key,
	);

	my $mime = $smime->get_mime;
	my $sign = $mime->stringify_body;

	my $signature_path = "$dst/signature";
	path($signature_path)->spew(decode_base64($sign));
}

sub package_raw_data {
	my ($dst) = @_;
	my $zip_path = "pushPackage.zip";

	my $zip = Archive::Zip->new;
	my @files = (@raw_files, 'manifest.json', 'signature');
	for my $file (@files) {
		$zip->addFile("$dst/$file", $file);
	}
	$zip->writeToFileNamed($zip_path) == AZ_OK
		or die "write error";

	print "created: " . $zip_path . "\n";

	path($dst)->remove_tree;
}

sub create_push_package {
	my $dst = 'pushPackage';
	make_path($dst, { mode => 0775 });

	copy_raw_push_package_files($dst);
	create_manifest($dst);
	create_signature($dst, $certificate_path, $private_key_path);
	package_raw_data($dst);
}

create_push_package;
exit;