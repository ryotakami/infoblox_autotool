use strict;
use Config::Tiny;
use Infoblox;
use warnings;
use Win32::OLE;
use utf8;
use Net::SMTP;
use Text::ParseWords;
use Encode 'from_to';
use open IO => ":encoding(cp932)"; 
binmode STDOUT, ':encoding(cp932)';
binmode STDERR, ':encoding(cp932)';
#config file read

my $cfg = Config::Tiny->read( 'Infoblox_autotool.ini' )or die("ファイルが読めません。");
my $infoblox_server = $cfg->{global}->{infoblox_server};
my $username = $cfg->{global}->{username};
my $password = $cfg->{global}->{password};
my $import_csvfolder = $cfg->{global}->{import_csvfolder};
my $export_csvfolder = $cfg->{global}->{export_csvfolder};
my $importfile_new = $cfg->{global}->{importfile_new};
my $inet_segment = $cfg->{global}->{inet_segment};
my $inet_dir = $cfg->{global}->{inet_conf_folder};
my $filter_file = $cfg->{global}->{blox_mac_filter};
my $mac_folder = $cfg->{global}->{blox_mac_folder};
my $log_output_folder = $cfg->{global}->{log_folder};
my $Inet_exe_folder = $cfg->{global}->{inet_exe_folder};
my $Inet_exe_file = $cfg->{global}->{inet_exe_file};
my $mac_filter_name = $cfg->{global}->{mac_filter};
my $list_folder = $cfg->{global}->{listfolder};
my $rotate_num = $cfg->{global}->{rotate_number};
my $sikii = $cfg->{check}->{sikii};

my $smtp_server = $cfg->{mail}->{smtp_server};
my $smtp_port = $cfg->{mail}->{smtp_port};
my $from = $cfg->{mail}->{mail_from};
my $mailto = $cfg ->{mail}->{mail_to};
#日本語対応
my $subject_txt;
my @mail_txt_kai;
my $mail_txt;
my $sabun_check0;
my $sabun_check1;
my $sabun_check2;
my $sabun_check3;
my $sabun_check4;
my $sabun_check5;
my $sabun_check6;
my $check1_old_value;
my $check1_new_value;
open(jap_conf,"Infoblox_autotool.ini")or die(&log_output("Infoblox_autotool.iniが開けません。\n",2));
	while(my $value_jap = <jap_conf>){
		chomp($value_jap);
		if(substr($value_jap,0,12) eq "mail_subject"){
			$subject_txt = substr($value_jap,13);
		}elsif(substr($value_jap,0,9) eq "mail_text"){
			#メールテキスト改行文字(\n)で改行する。打ち消しは考慮していない
			@mail_txt_kai = split(/\\n/, substr($value_jap,10));
			for(my $i=0;$mail_txt_kai[$i];$i++){
				$mail_txt .=$mail_txt_kai[$i]."\n";
			}
		}elsif(substr($value_jap,0,7) eq "check0="){
			$sabun_check0 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check1="){
			$sabun_check1 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check2="){
			$sabun_check2 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check3="){
			$sabun_check3 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check4="){
			$sabun_check4 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check5="){
			$sabun_check5 = substr($value_jap,7);
		}elsif(substr($value_jap,0,7) eq "check6="){
			$sabun_check6 = substr($value_jap,7);
		}elsif(substr($value_jap,0,17) eq "check1_old_value="){
			$check1_old_value = substr($value_jap,17);
		}elsif(substr($value_jap,0,17) eq "check1_new_value="){
			$check1_new_value = substr($value_jap,17);
		}
	}
close(jap_conf);

#date
my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(time);  
my $yyyymmdd = sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
my $yyyymmdd_d = $yyyymmdd;
my $logfile_yyyymmdd = $yyyymmdd;
#規定値

my $same_check1;
my $sabun_new_num0;
my $sabun_new_num1;
my $sabun_new_num2;
my $sabun_new_num3;
my $sabun_new_num4;
my $sabun_new_num5;
my $sabun_new_num6;
my $sabun_old_num0;
my $sabun_old_num1;
my $sabun_old_num2;
my $sabun_old_num3;
my $sabun_old_num4;
my $sabun_old_num5;
my $sabun_old_num6;
my @import_new_data;
my @import_old_data;

#1世代前ファイル名
my $importfile_old = substr($importfile_new,0,-4)."_1\.csv";

# 実行引数
# なし＝すべて実行
# 1=差分CSVファイル作成のみ
# 2=MAC登録/削除リスト作成のみ
# 3=DHCP/静的IPアドレス設定/削除リスト作成のみ
# 4=INetSec連携追加/削除リスト作成のみ
# 5=MACアドレス削除Infoblox/INetSec
# 6=静的IPアドレス削除Infoblox
#
if (@ARGV == 1){
	if($ARGV[0]==1){
		& csv_create;
		& rotate_file(1);
		& error_mail;
		exit(0);
	}elsif($ARGV[0]==2){
		opendir( mac_dir,$mac_folder) or die (&log_output("$mac_folder を開けません。\n",2));
		my @file = grep(/^MAC_address_/, readdir(mac_dir));
		closedir(mac_dir);
		if(@file==0){
			print "ファイルがありません。\n";
			exit(1);
		}elsif(@file==1){
			my $csv = $file[0];
			#$yyyymmdd = substr($file[0],12,14);
			& mac_infoblox($csv);
			& error_mail;
			& rotate_file(3);
			exit(0);
		}elsif(@file>1){
			my @filesort = sort { $b cmp $a } @file;
			my $csv = $filesort[0];
			#$yyyymmdd = substr($filesort[0],12,14);
			& mac_infoblox($csv);
			& error_mail;
			& rotate_file(3);
			exit(0);
		}
	}elsif($ARGV[0]==3){
		opendir( mac_dir,$mac_folder) or die (&log_output("$mac_folder を開けません。\n",2));
		my @file = grep(/^DHCP_register_/, readdir(mac_dir));
		closedir(mac_dir);
		if(@file==0){
			print "ファイルがありません。\n";
			exit(1);
		}elsif(@file==1){
			my $csv = $file[0];
			#$yyyymmdd = substr($file[0],14,14);
			#$yyyymmdd_d = $yyyymmdd;
			& dhcp_infoblox($csv);
			& rotate_file(3);
			& error_mail;
			exit(0);
		}elsif(@file>1){
			my @filesort =sort { $b cmp $a } @file;
			my $csv = $filesort[0];
			#$yyyymmdd = substr($filesort[0],14,14);
			#$yyyymmdd_d = $yyyymmdd;
			& dhcp_infoblox($csv);
			& rotate_file(3);
			& error_mail;
			exit(0);
		}
	
	}elsif($ARGV[0]==4){
		###登録と削除はセットで行うため、ファイルの有無だけ検索。個別実行するときは空レコードファイルを用意しておくこと
		opendir( sec_dir,$export_csvfolder) or die (&log_output("$inet_dir を開けません。\n",2));
		my @file = grep(/^INetSec_MAC_add_/, readdir(sec_dir));
		closedir(sec_dir);
		
		opendir( sec_dir,$export_csvfolder) or die (&log_output("$inet_dir を開けません。\n",2));
		my @file_d = grep(/^INetSec_MAC_del_/, readdir(sec_dir));
		closedir(sec_dir);

		my $add_csv;
		my $del_csv;
		
		if(@file==0or@file_d==0){
			&log_output("InetSec連携ファイル を開けません。\n",2);
			& rotate_file(3);
			& error_mail;
			exit(1);
		}else{
			if(@file==1){
				$add_csv = $file[0];
				$del_csv = $file_d[0];
				#$yyyymmdd = substr($file[0],16,14);
				#$yyyymmdd_d = substr($file_d[0],16,14);
			}elsif(@file>1){
				my @filesort = sort { $b cmp $a } @file;
				my @filesort_d = sort { $b cmp $a } @file_d;
				$add_csv = $filesort[0];
				$del_csv = $filesort_d[0];
				#$yyyymmdd = substr($filesort[0],16,14);
				#$yyyymmdd_d = substr($filesort_d[0],16,14);
			}
			& INetSec_import($add_csv, $del_csv);
			& rotate_file(3);
			& error_mail;

			exit(0);
		}

	}elsif($ARGV[0]==5){
		& mac_delete;
		& rotate_file(5);
		& error_mail;

	}elsif($ARGV[0]==6){
		& dhcp_delete;
		& rotate_file(6);
		& error_mail;
	}else{
		print "引数の値は[1-6]です。\n";
	}
}elsif(@ARGV >2){
	print "引数は１つです。\n";
}else{
	
	#新規ファイル名
	my $mac_csv  = "MAC_address_".$yyyymmdd.".csv";
	my $dhcp_csv = "DHCP_register_".$yyyymmdd.".csv";
	my $add_csv  = "INetSec_MAC_add_".$yyyymmdd.".csv";
	my $del_csv  = "INetSec_MAC_del_".$yyyymmdd_d.".csv";

	& csv_create;
	& mac_infoblox($mac_csv);
	& dhcp_infoblox($dhcp_csv);
	& INetSec_import($add_csv, $del_csv);
	& rotate_file(1);
	& error_mail;
}
#import csv file new or old
sub csv_create{
#import csv file (new)
	#検索
	opendir(import_dir,$import_csvfolder) or die (&log_output("$import_csvfolder を開けません。\n",3));
		my @importfile = grep(/^$importfile_new/, readdir import_dir);
		unless(@importfile){
			&log_output("連携ファイルがありません。\n",3);
			exit(1);
		}
	closedir import_dir;
	opendir(import_dir_old,$import_csvfolder) or die (&log_output("$import_csvfolder を開けません。\n",3));
		my @import_file_old = grep(/^$importfile_old/,readdir import_dir_old);
	closedir import_dir_old;
	#read csv
	my @import_new_data_a;
	open(import_csv_new,$import_csvfolder."\\".$importfile_new) or die(&log_output("$importfile_new を読み込めません。\n",3));
	my $p=0;
	while(<import_csv_new>){
		chomp($_);
			#&parse_lineの仕様で最後の「,」以降は値が取れないもよう。対応として末尾に「,」を入れ要素を-1にする
			$_ .= ",";
        @import_new_data_a = &parse_line(',',undef, $_);
        for(my $i=0;$i<scalar(@import_new_data_a)-1;$i++){
        	$import_new_data[$p][$i] = $import_new_data_a[$i];
        }
        $p=$p+1;
	}
	close(import_csv_new);
	$p = 0;
	if(scalar(@import_file_old)>0){
		open(import_csv_old,$import_csvfolder."\\".$importfile_old) or die(&log_output("$importfile_old を読み込めません。\n",3));
		my @import_old_data_a;
		while(<import_csv_old>){
			chomp($_);
			#&parse_lineの仕様で最後の「,」以降は値が取れないもよう。対応として末尾に「,」を入れ要素を-1にする
			$_ .= ",";
        	@import_old_data_a = &parse_line(',',undef, $_);
        	for(my $i=0;$i<scalar(@import_old_data_a)-1;$i++){
        		$import_old_data[$p][$i] = $import_old_data_a[$i];
        	}

        	$p=$p+1; 
    	}
		close(import_csv_old);
    }
		
	#今回データと前回データのレコード数比較
	if(scalar(@import_new_data)<scalar(@import_old_data)*$sikii){
		& log_output("今回データのレコード数が少ない為、処理を中止します。\n",2);
	}
	#ckeck項目の位置を検索
	# new
	for(my $i=0;$i<scalar(@{$import_new_data[0]});$i++){
		if($import_new_data[0][$i]eq$sabun_check0){
			$sabun_new_num0=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check1){
			$sabun_new_num1=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check2){
			$sabun_new_num2=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check3){
			$sabun_new_num3=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check4){
			$sabun_new_num4=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check5){
			$sabun_new_num5=$i;
		}elsif($import_new_data[0][$i]eq$sabun_check6){
			$sabun_new_num6=$i;
			
		}

	}
	if((defined $sabun_new_num0 and $sabun_new_num0 eq '') and (defined $sabun_new_num1 and $sabun_new_num1 ne '') and (defined $sabun_new_num2 and $sabun_new_num2 ne '') and (defined $sabun_new_num3 and $sabun_new_num3 ne '')
		 and (defined $sabun_new_num4 and $sabun_new_num4 ne '') and (defined $sabun_new_num5 and $sabun_new_num5 ne '') and (defined $sabun_new_num6 and $sabun_new_num6 ne '')){
		&log_output("$importfile_new のカラム名が一致しません。\n",2);
	}
	#MACアドレスの大文字の小文字化
	for(my $i=1;$i<scalar(@import_new_data);$i++){
		$import_new_data[$i][$sabun_new_num2] = lc $import_new_data[$i][$sabun_new_num2];
	}
	#old
	if(scalar(@import_old_data)>1){
		for(my $i=0;$i<scalar(@{$import_old_data[0]});$i++){
			if($import_old_data[0][$i]eq$sabun_check0){
				$sabun_old_num0=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check1){
				$sabun_old_num1=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check2){
				$sabun_old_num2=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check3){
				$sabun_old_num3=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check4){
				$sabun_old_num4=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check5){
				$sabun_old_num5=$i;
			}elsif($import_old_data[0][$i]eq$sabun_check6){
				$sabun_old_num6=$i;
			}
		}
		if((defined $sabun_old_num0 and $sabun_old_num0 eq'') and (defined $sabun_old_num1 and $sabun_old_num1 eq'') and (defined $sabun_old_num2 and $sabun_old_num2 eq'') and (defined $sabun_old_num3 and $sabun_old_num3 eq'')
			 and (defined $sabun_old_num4 and $sabun_old_num4 eq'') and (defined $sabun_old_num5 and $sabun_old_num5 eq'') and (defined $sabun_old_num6 and $sabun_old_num6 eq'')){
			&log_output("$importfile_old のカラム名が一致しません。\n",2);
		}
		#MACアドレスの大文字の小文字化
		for(my $i=1;$i<scalar(@import_old_data);$i++){
			$import_old_data[$i][$sabun_old_num2] = lc $import_old_data[$i][$sabun_old_num2];
		}

	}
	#前回レコードがデータ有、今回レコードがデータ無の場合はMAC削除、固定削除、INetSec削除
	open(mac_register,">>",$mac_folder."\\MAC_address_".$yyyymmdd.".csv") or die(&log_output("\\MAC_address_".$yyyymmdd.".csv が書き込みできません。\n",2));
	open(DHCP_register,">>",$mac_folder."\\DHCP_register_".$yyyymmdd.".csv") or die(&log_output("\\DHCP_address_".$yyyymmdd.".csv が書き込みできません。\n",2));
	
	$same_check1 = 0;
	
	for (my $i=1;$i<scalar(@import_old_data);$i++){

		# MAC登録が存在するか
		my $is_exist = 0;
		
		for(my $j=1;$j<scalar(@import_new_data);$j++){
			# MACアドレスで差分チェック
			if($import_old_data[$i][$sabun_old_num2] eq $import_new_data[$j][$sabun_new_num2]){
				$same_check1 = 1;
				last;
			}
		}
		
		# 前回レコードで除外申請日がある OR ドメイン参加かつ必須SW導入がある場合はMAC登録がある
		if(($import_old_data[$i][$sabun_old_num6]ne'') or (($import_old_data[$i][$sabun_old_num1] eq $check1_old_value) and ($import_old_data[$i][$sabun_old_num3]ne''))){
			$is_exist = 1;
		}
		
		# 引っかからないものかつ前回レコードに存在するものはMAC削除
		if($same_check1==0 and $is_exist==1 and $import_old_data[$i][$sabun_old_num2]ne''){
			print mac_register substr($import_old_data[$i][$sabun_old_num2],0,17).",remove\n";
			&log_output(substr($import_old_data[$i][$sabun_old_num2],0,17).",remove をMAC_address_$yyyymmdd.csv に追加しました。\n",0);
			#MAC削除のうち、ドメイン参加かつ除外申請受付日か必須SW導入日に日付有、静的IPアドレス申請受付日に日付ありでIPアドレス記入がある場合は静的IPアドレスがある為削除
			if(($import_old_data[$i][$sabun_old_num5]) and  ($import_old_data[$i][$sabun_old_num4]) and 
				(($import_old_data[$i][$sabun_old_num1]eq$check1_old_value) and ($import_old_data[$i][$sabun_old_num3]) or ($import_old_data[$i][$sabun_old_num6]))) {
				print DHCP_register substr($import_old_data[$i][$sabun_old_num2],0,17).",$import_old_data[$i][$sabun_old_num5],remove\n";
				&log_output(substr($import_old_data[$i][$sabun_old_num2],0,17).",$import_old_data[$i][$sabun_old_num5],remove をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
			}
		}
		$same_check1 = 0;
	}
	
	##今回レコードがデータ有、前回レコード→データ無＝MAC登録、固定削除、INetSec削除
	for (my $i=1;$i<scalar(@import_new_data);$i++){
		for(my $j=1;$j<scalar(@import_old_data);$j++){
			#MACアドレスと資産番号が一致の場合は他の項目チェック
			if(($import_new_data[$i][$sabun_new_num0]eq$import_old_data[$j][$sabun_old_num0]) and ($import_new_data[$i][$sabun_new_num2]eq$import_old_data[$j][$sabun_old_num2])){
		 		$same_check1=1;
				#前回レコードで除外申請日、またはドメイン参加と必須SW導入がある場合はMAC登録がある。
				if(($import_old_data[$j][$sabun_old_num6]ne'') or (($import_old_data[$j][$sabun_old_num1]eq$check1_old_value) and($import_old_data[$j][$sabun_old_num3]ne''))){
					#今回レコードで除外申請日、またはドメイン参加と必須SW導入がある場合はMAC登録維持
					if(($import_new_data[$i][$sabun_new_num6]ne'') or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and($import_new_data[$i][$sabun_new_num3]ne''))){
						#さらに前回静的IPアドレス申請日と静的IPアドレスがある→静的IPアドレス登録がある。
						if(($import_old_data[$j][$sabun_old_num4]ne'') and ($import_old_data[$j][$sabun_old_num5]ne'')){
							#今回レコードにIPがない場合は削除レコードとなる
							if((($import_new_data[$i][$sabun_new_num6]ne'') or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and($import_new_data[$i][$sabun_new_num3]ne'')))
								and (($import_new_data[$i][$sabun_new_num4]eq'') or ($import_new_data[$i][$sabun_new_num5]eq''))){
								print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],remove\n";
									&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],remove をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
							#今回レコードと前回レコードで静的IPアドレスが違う場合、静的IPアドレス変更する（削除して登録)、静的IPアドレスが一致する場合は何もしない。
							}elsif((($import_new_data[$i][$sabun_new_num6]ne'') or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and($import_new_data[$i][$sabun_new_num3]ne'')))
								and ($import_old_data[$j][$sabun_old_num5]ne$import_new_data[$i][$sabun_new_num5])){
								print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],removeforce\n";
								&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],removeforce をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
								print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add\n";
								&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
							}
						#前回レコードで静的IPアドレスがない場合、新に除外申請日があり、必須SW日とドメイン参加があり、静的IPアドレス申請日と静的IPアドレスがある場合は静的IPアドレス追加
						}elsif((($import_new_data[$i][$sabun_new_num6]ne'') or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and($import_new_data[$i][$sabun_new_num3]ne'')))
							and (($import_new_data[$i][$sabun_new_num4]ne'') and ($import_new_data[$i][$sabun_new_num5]ne''))){
							print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add\n";
							&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
						}
					#MAC登録維持されない＝MAC削除、さらにMAC削除されるため、静的IPアドレスが登録されていれば削除
					}else{
						print mac_register substr($import_new_data[$i][$sabun_new_num2],0,17).",remove\n";
						&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",remove をMAC_address_$yyyymmdd.csv に追加しました。\n",0);
						#前回レコードに静的IPアドレス申請日と静的IPアドレスがある場合、静的IPアドレス登録がすでにされているため、今回のカラム状況を問わず静的IPアドレス削除。
						if(($import_old_data[$j][$sabun_old_num4]ne'') and ($import_old_data[$j][$sabun_old_num5]ne'')){
							print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],remove\n";
							&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_old_data[$j][$sabun_old_num5],remove をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
						}
					}
				}else{
					#前回レコードでMAC登録がないもののうち、今回レコードで除外申請日、またはドメイン参加と必須SW導入がある場合はMACアドレス登録
					if(($import_new_data[$i][$sabun_new_num6]ne'') or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and($import_new_data[$i][$sabun_new_num3]ne''))){
						print mac_register substr($import_new_data[$i][$sabun_new_num2],0,17).",add\n";
						&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",add をMAC_address_$yyyymmdd.csv に追加しました。\n",0);
						#さらに静的IPアドレス申請日と静的IPアドレスがある場合は静的IPアドレス追加
						if(($import_new_data[$i][$sabun_new_num4]ne'') and($import_new_data[$i][$sabun_new_num5]ne'')){
							print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add\n";
							&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
						}
					}
				}
			}
		}
		#新規登録分
		unless($same_check1==1){
			# MACアドレスのバリデーション
			if(&is_macaddr($import_new_data[$i][$sabun_new_num2]) eq 1){
				# MACアドレス登録がないもののうち、今回レコードで除外申請日またはドメイン参加と必須SW導入がある場合MACアドレス登録
				if(($import_new_data[$i][$sabun_new_num6]ne"") or (($import_new_data[$i][$sabun_new_num1]eq$check1_new_value) and ($import_new_data[$i][$sabun_new_num3]ne""))){
					print mac_register substr($import_new_data[$i][$sabun_new_num2],0,17).",add\n";
					&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",add をMAC_address_$yyyymmdd.csv に追加しました。\n",0);
					#さらに静的IPアドレス申請日と静的IPアドレスがある場合静的Ip追加
					if(($import_new_data[$i][$sabun_new_num4]ne"") and($import_new_data[$i][$sabun_new_num5]ne"")){
						print DHCP_register substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add\n";
						&log_output(substr($import_new_data[$i][$sabun_new_num2],0,17).",$import_new_data[$i][$sabun_new_num5],add をDHCP_register_$yyyymmdd.csv に追加しました。\n",0);
					}
				}
			}
			else{
				&log_output("$import_new_data[$i][$sabun_new_num2] は重複したMACアドレスのためスキップしました。\n",1);
			}
		}
		$same_check1=0;
	}

	close(mac_register);
	close(DHCP_register);
	
	###INetSec 連携ファイル作成
	open(my $segment_all,$inet_dir."\\".$inet_segment)or die(&log_output("$inet_segment が開けません。\n",2));
		my @segment_group = map { chomp($_); $_ } <$segment_all>;
	close( $segment_all);
	open(my $mac_adddel_csv,$mac_folder."\\MAC_address_".$yyyymmdd.".csv")or die(&log_output("\\MAC_address_$yyyymmdd.csv が開けません。\n",2));
		my @mac_add_del = map{chomp;[split /,/ ]} <$mac_adddel_csv>;
	close($mac_adddel_csv);
	open(InetSec_register,">",$export_csvfolder."\\INetSec_MAC_add_".$yyyymmdd.".csv") or die(&log_output("\\INetSec_MAC_add_yyyymmdd.csv に書き込みできません。\n",2));
	open(InetSec_delete,">",$export_csvfolder."\\INetSec_MAC_del_".$yyyymmdd.".csv") or die(&log_output("\\INetSec_MAC_del_$yyyymmdd.csv に書き込みできません。\n",2));
	print InetSec_register "MACアドレス,セグメントグループ,承認ステータス,機器種別,機器種別詳細,機種名,OS種別,メーカー名,機器属性の自動更新,機器備考1,機器備考2,機器備考3,項目1,項目2,項目3,項目4,項目5,有効期間開始日,有効期間終了日,IPアドレスの変更通知,ベンダー名,IPアドレス,ホスト名,NetBIOS名,役割,新規登録日時,利用申請日時,承認日時,最終検知日,検知セグメント名,割り当てIPアドレス\n";
	print InetSec_delete "MACアドレス,セグメントグループ,承認ステータス,機器種別,機器種別詳細,機種名,OS種別,メーカー名,機器属性の自動更新,機器備考1,機器備考2,機器備考3,項目1,項目2,項目3,項目4,項目5,有効期間開始日,有効期間終了日,IPアドレスの変更通知,ベンダー名,IPアドレス,ホスト名,NetBIOS名,役割,新規登録日時,利用申請日時,承認日時,最終検知日,検知セグメント名,割り当てIPアドレス\n";

	for(my $i=0;$i<scalar(@mac_add_del);$i++){
		
		# MACアドレスが空ならスキップ
		next if($mac_add_del[$i][0] eq '');
		
		# MACアドレスのバリデーション
		if(&is_macaddr($mac_add_del[$i][0]) eq 0){
			&log_output("$mac_add_del[$i][0] は不正なMACアドレスのためスキップしました。\n",1);
			next;
		}
		
		# MACアドレスの重複チェック
		if(&is_duplicate(\@mac_add_del, $i) eq 1){
			&log_output("$mac_add_del[$i][0] は重複したMACアドレスのためスキップしました。\n",1);
			next;
		}
		
		if($mac_add_del[$i][1]eq"add"){
			for(my $j=0;$j<scalar(@segment_group);$j++){
				print InetSec_register "$mac_add_del[$i][0],$segment_group[$j],許可,,,,,,更新する,,,,,,,,,,,,,,,,,,,,,,\n";
				#&log_output("$mac_add_del[$i][0],$segment_group[$j] をINetSec_MAC_add_$yyyymmdd.csv に追加しました。\n",0);
			}
			&log_output("$mac_add_del[$i][0] をINetSec_MAC_add_$yyyymmdd.csv に追加しました。\n",0);
		}elsif($mac_add_del[$i][1]eq"remove"){
			for(my $j=0;$j<scalar(@segment_group);$j++){
				print InetSec_delete "$mac_add_del[$i][0],$segment_group[$j],,,,,,,,,,,,,,,,,,,,,,,,,,,,,\n";
				#&log_output("$mac_add_del[$i][0],$segment_group[$j] をINetSec_MAC_del_$yyyymmdd.csv に追加しました。\n",0);
			}
			&log_output("$mac_add_del[$i][0] をINetSec_MAC_del_$yyyymmdd.csv に追加しました。\n",0);
		}else{
			&log_output("\\MAC_address_".$yyyymmdd.".csv でadd、del以外の指定があります。\n",1);
			exit(1);
		}
	}
	close(InetSec_delete);
	close(InetSec_register);
	&log_output("正常に差分抽出処理を完了しました。\n",0);
}

#MAC_address
sub mac_infoblox{
	
	#対象CSVファイル
	my $csv = $_[0];

	#MAC登録・削除CSVファイル読み込み
	open(my $mac_adddel_csv,$mac_folder."\\". $csv) or die(&log_output("$csv が開けません。\n",2));
	my @mac_add_del = map{chomp;[split /,/ ]} <$mac_adddel_csv>;
	close($mac_adddel_csv);
	
	#削除リストファイルオープン
	#リスト更新用(引数５実行後ここでファイルが作られる)
    unless(-f $list_folder."\\MAC_deletelist.csv"){
   		open(new_file,">",$list_folder."\\MAC_deletelist.csv")or die(&log_output("MAC_deletelist.csv が開けません。\n",2));
   		close(new_file);
   	}
	open (my $del_listfile,$list_folder."\\MAC_deletelist.csv")or die(&log_output("MAC_deletelist.csv が開けません。\n",2));
	chomp($del_listfile);
	my @del_listfile_new = <$del_listfile>;
	close($del_listfile);
	
	for(my $i=0;$del_listfile_new[$i];$i++){
		chomp($del_listfile_new[$i]);
	}

	#session作成
	if(scalar(@mac_add_del)eq"0"){
		&log_output("MACアドレス設定:登録・削除するMACアドレスはありません。\n",0);
	}else{
		my $session_mac = Infoblox::Session->new(
		                master   => $infoblox_server,
		                username => $username,
		                password => $password,
		 );
		if ($session_mac->status_code()){
			die(&log_output("Infobloxに接続できませんでした。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",2));
		}
		&log_output("infobloxと接続しました。\n",0);
			#macフィルター検索
			my @filter_search = $session_mac->search(
					object	=> "Infoblox::DHCP::Filter::MAC",
					name	=> $mac_filter_name,
			);
			unless(@filter_search){
				&log_output("MACアドレス設定：MACフィルターが存在しません。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
		}
		my @mac_search_obj;
		my $mac_obj;
		my $mac_add_filter;
		my $mac_del_filter;
		for(my $i=0;$i<1;$i++){
			for(my $j=0;$j<scalar(@mac_add_del);$j++){
				#MACアドレスの大文字の小文字化
				$mac_add_del[$j][0] = lc $mac_add_del[$j][0];
				#MACアドレスが登録されているか検索
				@mac_search_obj = $session_mac->get(
						object => "Infoblox::DHCP::MAC",
						mac    => $mac_add_del[$j][0],
						filter => $mac_filter_name,
				);
				if(@mac_search_obj){
					if($mac_add_del[$j][1]eq"add"){
						&log_output("MACアドレス設定(登録):$mac_add_del[$j][0] はすでに登録されています。\n",0);
							#登録しようとしたMACアドレスが削除リストにある場合は削除リストから削除			
							for(my $k=0;$k<=scalar(@del_listfile_new);$k++){
							if(defined $del_listfile_new[$k]){
								unless($del_listfile_new[$k] eq ''){
									if($mac_add_del[$j][0] eq $del_listfile_new[$k]){
										$del_listfile_new[$k] = '';
										#実際のファイル記述は「#削除リストファイルオープン」で行われる。
										&log_output("MACアドレス設定：$mac_add_del[$j][0] をMAC_deletelist.csvから削除しました。\n",0);
									}
								}
							}
						}
					}elsif($mac_add_del[$j][1]eq"remove"){
						#削除リストとの重複チェック
						if(grep{$_ eq $mac_add_del[$j][0]} @del_listfile_new){
							&log_output("MACアドレス設定：$mac_add_del[$j][0] はすでにMAC_deletelist.csvに記載されています。\n",0);
						}else{
							#削除レコードの場合はそのまま削除リストに追記
							push(@del_listfile_new,"$mac_add_del[$j][0]");
							& log_output($mac_add_del[$j][0]." をInfoblox連携削除リストに追加しました。\n",0);

						}
						
					}
				}else{
					if($mac_add_del[$j][1]eq"add"){
						$mac_obj = Infoblox::DHCP::MAC->new(
								"mac"		=> $mac_add_del[$j][0],
								"filter"	=> $mac_filter_name,
						);
						$mac_add_filter = $session_mac->add($mac_obj);
						if($mac_add_filter){
							&log_output("MACアドレス設定(登録):$mac_add_del[$j][0] を登録しました。\n",0);
							#登録したMACアドレスが削除リストにある場合は削除リストから削除			
							for(my $k=0;$k<=scalar(@del_listfile_new);$k++){
							if(defined $del_listfile_new[$k]){
								unless($del_listfile_new[$k] eq ''){
									if($mac_add_del[$j][0] eq $del_listfile_new[$k] ){
										$del_listfile_new[$k] = '';
										#実際のファイル記述は「#削除リストファイルオープン」で行われる。
										&log_output("MACアドレス設定：$mac_add_del[$j][0] をMAC_deletelist.csvから削除しました。\n",0);
									}
								}
							}
							}
						}else{
							&log_output("MACアドレス設定(登録):$mac_add_del[$j][0] を登録できませんでした。".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
						}
					}elsif($mac_add_del[$j][1]eq"remove"){
						&log_output("MACアドレス設定(削除):$mac_add_del[$j][0] はすでに登録されていません。\n",0);
					}
				}
			}
		}
	#logout
	$session_mac->logout();
	#削除リストファイルオープン
	open(new_del_listfile,">",$list_folder."\\MAC_deletelist.csv")or die(&log_output("MAC_deletelist.csv が開けません。\n",2));
		for(my $i=0;$i<@del_listfile_new;$i++){
			unless($del_listfile_new[$i] eq ''){
				print new_del_listfile $del_listfile_new[$i]."\n";
			}
		}
	close(new_del_listfile);
	& log_output("Infoblox連携削除リストを更新しました。\n",0);
	}
}

sub dhcp_infoblox{

	# 対象CSVファイル
	my $csv = $_[0];
	
	#静的IPアドレス登録・削除CSVファイル読み込み
	open(my $dhcp_register_csv,$mac_folder."\\".$csv) or die(&log_output("DHCP_register_$yyyymmdd.csv が開けません。\n",2));
	my @dhcp_register = map{chomp;[split /,/ ]} <$dhcp_register_csv>;
	close($dhcp_register_csv);
   	
   	if(scalar(@dhcp_register)eq"0"){
		&log_output("静的IPアドレス設定：登録・削除するIPアドレスはありません。\n",0);
		return;
	}
   	
   	#削除リストファイルオープン
	#リスト更新用(引数５実行後ここでファイルが作られる)
    unless(-f $list_folder."\\DHCP_deletelist.csv"){
   		open(new_file,">",$list_folder."\\DHCP_deletelist.csv") or die(&log_output("DHCP_deletelist.csv が開けません。\n",2));
   		close(new_file);
   	}
   	
	open (my $del_listfile,$list_folder."\\DHCP_deletelist.csv") or die(&log_output("DHCP_deletelist.csv が開けません。\n",2));

	chomp($del_listfile);
	my @del_listfile_new = <$del_listfile>;
	close($del_listfile);
	
	for(my $i=0;$del_listfile_new[$i];$i++){
		chomp($del_listfile_new[$i]);
	}
	
	#session作成
	my $session_dhcp = Infoblox::Session->new(
		master   => $infoblox_server,
		username => $username,
		password => $password,
	);
	if ($session_dhcp->status_code()){
		die(&log_output("静的IPアドレス設定：Infobloxに接続できませんでした。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",2));
	}
	
	&log_output("静的IPアドレス設定：infobloxと接続しました。\n",0);
		
	#登録／削除
	for(my $i=0;$i<scalar(@dhcp_register);$i++){
	
		#MACアドレスの大文字の小文字化
		$dhcp_register[$i][0] = lc $dhcp_register[$i][0];
		
		##networkオブジェクト検索
		my @network_search_obj = $session_dhcp->search(
			"object"	=> "Infoblox::DHCP::Network",
			"contains_address" => $dhcp_register[$i][1],
		);
		
		unless(@network_search_obj){
			&log_output("静的IPアドレス設定：登録先networkがありません。＞$dhcp_register[$i][1]:".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
			next;
		}
		
		# DHCP削除リストへの記載
		if($dhcp_register[$i][2] eq "remove"){
			if(grep{$_ eq "$dhcp_register[$i][0]\,$dhcp_register[$i][1]"} @del_listfile_new){
				&log_output("静的IPアドレス設定：$dhcp_register[$i][0],$dhcp_register[$i][1] はすでにDHCP_deletelist.csvに記載されています。\n",0);
			}
			else{
				push(@del_listfile_new,"$dhcp_register[$i][0],$dhcp_register[$i][1]");
				&log_output("静的IPアドレス設定：$dhcp_register[$i][0],$dhcp_register[$i][1] をDHCP_deletelist.csvに追加しました。\n",0);
			}
			next;
		}
		
		#アドレスオブジェクト検索
		my @ip_address_search = $session_dhcp->search(
			object	=> "Infoblox::DHCP::FixedAddr",
			ipv4addr=> $dhcp_register[$i][1],
			network=> $network_search_obj[0]->network(),
			mac=>$dhcp_register[$i][0],
		);
		
		#アドレスオブジェクトが存在し、指示は削除なので削除（IPアドレスが一意のオブジェクトの為、静的IPアドレス変更でも削除
		if((@ip_address_search) && ($ip_address_search[0]->mac()eq$dhcp_register[$i][0]) && ($dhcp_register[$i][2]eq"removeforce")){
			my $ip_remove = $session_dhcp->remove($ip_address_search[0]);
			if($ip_remove){
				&log_output("静的IPアドレス設定：$dhcp_register[$i][1] を削除しました。\n",0);
			}else{
				&log_output("静的IPアドレス設定：$dhcp_register[$i][1] を削除できませんでした。".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
			}
		}
		elsif((@ip_address_search) && ($ip_address_search[0]->mac()ne$dhcp_register[$i][0]) && ($dhcp_register[$i][2]eq"removeforce")){
			&log_output("静的IPアドレス設定：$dhcp_register[$i][1] は他の機器が登録されているため、削除処理をキャンセルします。\n",1);
		}
		elsif((@ip_address_search) && ($ip_address_search[0]->mac()eq$dhcp_register[$i][0]) && ($dhcp_register[$i][2]eq"add")){
			&log_output("静的IPアドレス設定：$dhcp_register[$i][1] はすでに登録されています。\n",0);
		}
		elsif((@ip_address_search) && ($ip_address_search[0]->mac()ne$dhcp_register[$i][0]) && ($dhcp_register[$i][2]eq"add")){
			&log_output("静的IPアドレス設定：$dhcp_register[$i][1] は$ip_address_search[0] で登録されているため、登録できません。\n",1);
		}
		else{
			#検索できた場合終了
			if($dhcp_register[$i][2]eq"removeforce"){
				&log_output("静的IPアドレス設定：$dhcp_register[$i][1] が登録されていないため、削除処理をキャンセルします。\n",0);
			}
			else{
				my $ip_addention = Infoblox::DHCP::FixedAddr->new(
					ipv4addr	=> $dhcp_register[$i][1],
					network		=> $network_search_obj[0]->network(),
					mac			=> $dhcp_register[$i][0],
				);
				my $ip_address_add = $session_dhcp->add($ip_addention);
				if($ip_address_add){
					&log_output("静的IPアドレス設定:$dhcp_register[$i][1]を登録しました。\n",0);
				}
				else{
					&log_output("静的IPアドレス設定:$dhcp_register[$i][0]は$dhcp_register[$i][1]以外の静的IPアドレスで登録があります。\n",1);
				}
			}
		}
	}
	
	#logout
	$session_dhcp->logout();
	
	#削除リストファイルオープン
	open(new_del_listfile,">",$list_folder."\\DHCP_deletelist.csv") or die(&log_output("DHCP_deletelist.csv が開けません。\n",2));
	for(my $i=0;$i<@del_listfile_new;$i++){
		unless($del_listfile_new[$i] eq ''){
			print new_del_listfile $del_listfile_new[$i]."\n";
		}
	}
	close(new_del_listfile);
}

sub INetSec_import{

	#対象CSVファイル
	my ($add_csv, $del_csv) = @_;

	my @buffer_add;
	my $line_add;
	my @buffer_del;
	my $line_del;
	my $infoblox_del;
	
	#連携ファイル存在確認
	unless(-f $export_csvfolder."\\".$add_csv){
		& log_output("INetSec連携:$add_csv がありません。\n",2);
		#引き数無しで実行時はAssetmentNeo連携ファイルをリネーム
		unless($ARGV[0]){
			rename($import_csvfolder."\\".$importfile_new, $import_csvfolder."\\".substr($importfile_new,0,-4)."_".$yyyymmdd.".csv")
				or die(&log_output("INetSec連携:$importfile_new がありません。\n"),2);
		}
		& error_mail;
		exit(1);
	}
	
	unless(-f $export_csvfolder."\\".$del_csv){
		& log_output("INetSec連携:$del_csv がありません。\n",2);
		#引き数無しで実行時はAssetmentNeo連携ファイルをリネーム
		unless($ARGV[0]){
			rename($import_csvfolder."\\".$importfile_new, $import_csvfolder."\\".substr($importfile_new,0,-4)."_".$yyyymmdd.".csv");
		}
		& error_mail;
		exit(1);
	}
	#登録レコード数確認
	open(line_check_add,$export_csvfolder."\\".$add_csv)or die(&log_output("INetSec連携:$add_csv が開けません。\n"),2);
		@buffer_add = <line_check_add>;
		$line_add = scalar(@buffer_add);
	close(line_check_add);
	#削除レコード数確認
	open(line_check_del,$export_csvfolder."\\".$del_csv)or die(&log_output("INetSec連携:$del_csv が開けません。\n"),2);
		@buffer_del = <line_check_del>;
		$line_del = scalar(@buffer_del);
	close(line_check_del);

	#登録
	if($line_add>1){
	#INetsecインポート実施とERRORLEVELの取得をbatファイルにする。
	my $code_exe;
	open(exe_cmd,">",$export_csvfolder."\\INetSec_exe.bat")or die(&log_output("INetSec_exe.batが作成できません。\n",2));
		print exe_cmd "\"".$Inet_exe_folder."\\".$Inet_exe_file."\" ".$export_csvfolder."\\INetSec_MAC_add_".$yyyymmdd.".csv -s -h on","\n";
		print exe_cmd "echo %ERRORLEVEL% > \"".$export_csvfolder."\\result_add.txt","\n";
	close(exe_cmd);
	system("\"".$export_csvfolder."\\INetSec_exe.bat");
	#ツールのプロセスのERRORLEVELを読み込む
	open(exe_cmd,$export_csvfolder."\\result_add.txt")or die(log_output("result_add.txtが開けません。\n",2));
	$code_exe = <exe_cmd>;
	chomp($code_exe);
	close(exe_cmd);
	
	#一時ファイルの削除
	unlink($export_csvfolder."\\result_add.txt") or die(&log_output("$Inet_exe_file 実行時の一時ファイルresult_add.txtの削除に失敗しました。\n",1));
	unlink($export_csvfolder."\\INetSec_exe.bat") or die(&log_output("$Inet_exe_file 実行時の一時ファイルINetSec_exe.batの削除に失敗しました。\n",1));

		if($code_exe == 0){
			&log_output("INetSec連携:INetSecへの登録が正常終了しました。\n",0);
				#正常終了時に今回ファイル内に削除リスト内と同ＭＡＣアドレスかつ同セグメントグループがある場合は削除リストから削除。(ファイルがない場合ここで作成される）
				unless(-f $list_folder."\\INetSec_deletelist.csv"){
					open(new_file,">",$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec_deletelist.csv が開けません。\n",2));
					close(new_file);
				}
				open (my $del_INet_listfile,$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec_deletelist.csv が開けません。\n",2));
					my @del_INet_listfile_new = <$del_INet_listfile>;
				close($del_INet_listfile);
				for(my $i=0;$del_INet_listfile_new[$i];$i++){
					unless($del_INet_listfile_new[$i] eq ''){
						for(my $j=1;$buffer_add[$j];$j++){
							if(substr($del_INet_listfile_new[$i],0,index($del_INet_listfile_new[$i],',',index($del_INet_listfile_new[$i],',')+1)) eq substr($buffer_add[$j],0,index($buffer_add[$j],',',index($buffer_add[$j],',')+1))){
								$del_INet_listfile_new[$i]='';
								&log_output("INetSec連携：".substr($buffer_add[$j],0,index($buffer_add[$j],',',index($buffer_add[$j],',')+1))."をINetSec_deletelist.csvから削除しました。\n",0);
							}
						}
					}
				}
				#削除リストファイルを更新
				open(del_file_INet,">",$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec_deletelist.csv が開けません。2\n",2));
					for(my $i=0;$del_INet_listfile_new[$i];$i++){
						unless($del_INet_listfile_new[$i] eq ''){
							print del_file_INet $del_INet_listfile_new[$i];
						}
					}
					& log_output("INetSec連携削除リストの削除分を更新しました。\n",0);
				close(del_file_INet);
		}elsif($code_exe == 3){
			&log_output("INetSec連携:$Inet_exe_file の実行環境が不正ため処理を続行できません。\n",1);
		}elsif($code_exe == 8){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、SQL サーバが起動していません。\n",1);
		}elsif($code_exe == 9){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、指定したファイルが存在しません。\n",1);
		}elsif($code_exe == 10){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、ファイルの形式に誤りがあります。\n",1);
		}elsif($code_exe == 11){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、ファイルの指定形式に誤りがあります。\n",1);
		}elsif($code_exe == 12){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、コマンドの引数に誤りがあります。\n",1);
		}elsif($code_exe == 13){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、制限値を超えました。\n",1);
		}elsif($code_exe == 14){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、入力データに誤りがあります。\n",1);
		}elsif($code_exe == 99){
			&log_output("INetSec連携:$Inet_exe_file の実行をしましたが、内部エラーが発生しました。\n",1);
		}
	}else{
		& log_output("登録レコードがない為、追加処理をスキップします。\n",0);
	}
	
	
	#削除
	#登録レコードがない場合はここで削除リストを作成
	unless(-f $list_folder."\\INetSec_deletelist.csv"){
		open(new_file,">",$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec_deletelist.csv が開けません。\n",2));
		close(new_file);
	}
	#今回削除ファイルと削除リストを比較し、削除するMACアドレスが重複するときは追記しない。
   	open (my $del_INet_listfile,$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec_deletelist.csv が開けません。1\n",2));
		my @del_INet_listfile_del = <$del_INet_listfile>;
	close($del_INet_listfile);

	open(delete_list,">>",$list_folder."\\INetSec_deletelist.csv")or die(&log_output("INetSec連携:INetSec_deletelist.csv が開けません。\n",2));
	my $check_del=0;
	if($line_del>1){
		for(my $i=1;$buffer_del[$i];$i++){
			for(my $j=0;$del_INet_listfile_del[$j];$j++){
				if($buffer_del[$i] eq $del_INet_listfile_del[$j]){
					$check_del=1;
				}
			}
			unless($check_del==1){
				print delete_list $buffer_del[$i];
				&log_output("INetSec連携：".substr($buffer_del[$i],0,index($buffer_del[$i],',',index($buffer_del[$i],',')+1))."をINetSec_deletelist.csvに追加しました。\n",0);
			}
			$check_del=0;
		}
	& log_output("INetSec連携削除リストの追加分を更新しました。\n",0);
	}
	close(delete_list);
}

sub mac_delete{

	my @mac_search_obj;
	my $mac_del_filter;

	#infoblox連携削除リストファイル確認
	unless(-f $list_folder."\\MAC_deletelist.csv"){
		& log_output("Infoblox連携削除ファイルがありません。\n",2);
	}
	#INetSec連携削除リストファイル確認
	unless(-f $list_folder."\\INetSec_deletelist.csv"){
		& log_output("INetSec連携削除ファイルがありません。\n",2);
	}

	#infoblox連携削除リストファイルの読み込み
	open(my $infoblox_del,$list_folder."\\MAC_deletelist.csv")or die(&log_output("MACアドレス削除処理:MAC_deletelist.csv が開けません。\n",2));
		chomp($infoblox_del);
		my @infoblox_dellist = <$infoblox_del>;
	close($infoblox_del);
	if(scalar(@infoblox_dellist)<1){
		&log_output("MACアドレス削除:MAC_deletelist.csv に削除対象レコードがありません。\n",2);
	}
	#Infobloxとsessionを張る
	my $session_mac = Infoblox::Session->new(
	                master   => $infoblox_server,
	                username => $username,
	                password => $password,
	 );
	if ($session_mac->status_code()){
		die(&log_output("Infobloxに接続できませんでした。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",2));
	}
	#Macfilter検索
	my @filter_search = $session_mac->search(
			object	=> "Infoblox::DHCP::Filter::MAC",
			name	=> $mac_filter_name,
	);

	unless(@filter_search){
		&log_output("MACアドレス設定：MACフィルターが存在しません。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",2);
	}
	for(my $i=0;$infoblox_dellist[$i];$i++){
		chomp($infoblox_dellist[$i]);
		$infoblox_dellist[$i] = lc $infoblox_dellist[$i];
		#MACアドレスが登録されているか検索
		@mac_search_obj = $session_mac->get(
				object => "Infoblox::DHCP::MAC",
				mac    => $infoblox_dellist[$i],
				filter => $mac_filter_name,
		);
		if(@mac_search_obj){
			$mac_del_filter = $session_mac->remove( $mac_search_obj[0]);
			if(Infoblox::status_code()==0){
				&log_output("MACアドレス設定(削除):$infoblox_dellist[$i] を削除しました。\n",0);
			}else{
				&log_output("MACアドレス設定(削除):$infoblox_dellist[$i] を削除できませんでした。".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
			}
		}
	}
	$session_mac->logout();
	&log_output("MACアドレス設定(削除)が終了しました。\n",0);

	#INetSec連携ファイルリスト読み込み
	my $code_exe;
	open(my $inet_del,$list_folder."\\INetSec_deletelist.csv")or die(&log_output("MACアドレス削除処理:INetSec_deletelist.csv が開けません。\n",2));
		chomp($inet_del);
		my @inet_dellist = <$inet_del>;
	close($inet_del);
	if(scalar(@inet_dellist)<1){
		&log_output("MACアドレス削除:INetSec_deletelist.csv に削除対象レコードがありません。\n",0);
	return;
	}
		
	#ツールのプロセスのERRORLEVELにインポート実行プロセスのERRORLEVELを一時ファイル記入
	open(exe_cmd,">",$export_csvfolder."\\INetSec_exe.bat")or die(&log_output("INetSec_exe.batが作成できません。\n",2));
		print exe_cmd "\"".$Inet_exe_folder."\\".$Inet_exe_file."\" ".$list_folder."\\INetSec_deletelist.csv -d -s","\n";
		print exe_cmd "echo %ERRORLEVEL% > \"".$export_csvfolder."\\result_del.txt","\n";
	close(exe_cmd);
	system("\"".$export_csvfolder."\\INetSec_exe.bat");
	#ツールのプロセスのERRORLEVELにインポート実行プロセスのERRORLEVELを代入
	open(exe_cmd,$export_csvfolder."\\result_del.txt")or die(log_output("result_del.txtが開けません。\n",2));
	$code_exe = <exe_cmd>;
	chomp($code_exe);
	close(exe_cmd);
	unlink($export_csvfolder."\\result_del.txt") or die(&log_output("$Inet_exe_file 実行時の１時ファイルresult_del.txtの削除に失敗しました。\n",1));
	unlink($export_csvfolder."\\INetSec_exe.bat") or die(&log_output("$Inet_exe_file 実行時の一時ファイルINetSec_exe.batの削除に失敗しました。\n",1));

	if($code_exe == 0){
		&log_output("INetSec からの削除が正常終了しました。\n",0);
	}elsif($code_exe == 3){
		&log_output("$Inet_exe_file の実行環境が不正ため処理を続行できません。\n",1);
	}elsif($code_exe == 8){
		&log_output("$Inet_exe_file の実行をしましたが、SQL サーバが起動していません。\n",1);
	}elsif($code_exe == 9){
		&log_output("$Inet_exe_file の実行をしましたが、指定したファイルが存在しません。\n",1);
	}elsif($code_exe == 10){
		&log_output("$Inet_exe_file の実行をしましたが、ファイルの形式に誤りがあります。\n",1);
	}elsif($code_exe == 11){
		&log_output("$Inet_exe_file の実行をしましたが、ファイルの指定形式に誤りがあります。\n",1);
	}elsif($code_exe == 12){
		&log_output("$Inet_exe_file の実行をしましたが、コマンドの引数に誤りがあります。\n",1);
	}elsif($code_exe == 13){
		&log_output("$Inet_exe_file の実行をしましたが、制限値を超えました。\n",1);
	}elsif($code_exe == 14){
		&log_output("$Inet_exe_file の実行をしましたが、入力データに誤りがあります。\n",1);
	}elsif($code_exe == 99){
		&log_output("$Inet_exe_file の実行をしましたが、内部エラーが発生しました。\n",1);
	}
}

sub dhcp_delete{

	#infoblox連携削除リストファイル確認
	unless(-f $list_folder."\\DHCP_deletelist.csv"){
		&log_output("DHCP_deletelist.csv がありません。\n",2);
	}

	#infoblox連携削除リストファイルの読み込み
	open(my $infoblox_del,$list_folder."\\DHCP_deletelist.csv") or die(&log_output("静的IPアドレス削除:DHCP_deletelist.csv が開けません。\n",2));
	chomp($infoblox_del);
	my @infoblox_dellist = <$infoblox_del>;
	close($infoblox_del);
	
	if(scalar(@infoblox_dellist)<1){
		&log_output("静的IPアドレス削除:DHCP_deletelist.csv に削除対象レコードがありません。\n",2);
	}
	
	#Infobloxとsessionを張る
	my $session = Infoblox::Session->new(
		master   => $infoblox_server,
		username => $username,
		password => $password,
	);
	
	if ($session->status_code()){
		die(&log_output("Infobloxに接続できませんでした。:".Infoblox::status_code().":".Infoblox::status_detail()."\n",2));
	}

	&log_output("静的IPアドレス削除：infobloxと接続しました。\n",0);

	#削除
	for(my $i=0;$infoblox_dellist[$i];$i++){
		
		chomp $infoblox_dellist[$i];
		my @line = split(/,/, $infoblox_dellist[$i]);
	
		my $mac = $line[0];
		my $ip  = $line[1];

		#networkオブジェクト検索
		my @network_search_obj = $session->search(
			"object"	=> "Infoblox::DHCP::Network",
			"contains_address" => $ip,
		);
		
		unless(@network_search_obj){
			&log_output("静的IPアドレス削除：登録先networkがありません。＞$ip:".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
			next;
		}
		
		#アドレスオブジェクト検索
		my @ip_address_search = $session->search(
			object	=> "Infoblox::DHCP::FixedAddr",
			ipv4addr=> $ip,
			network=> $network_search_obj[0]->network(),
			mac=>$mac,
		);
		
		if(@ip_address_search){
			my $ip_remove = $session->remove($ip_address_search[0]);
			if($ip_remove){
				&log_output("静的IPアドレス削除：$mac,$ip を削除しました。\n",0);
			}else{
				&log_output("静的IPアドレス削除：$mac,$ip を削除できませんでした。".Infoblox::status_code().":".Infoblox::status_detail()."\n",1);
			}
		}
		else{
			&log_output("静的IPアドレス削除：$mac,$ip は登録されていません。\n",0);
		}
	}
	
	$session->logout();
	&log_output("静的IPアドレス削除が終了しました。\n",0);

}

#logを作成。エラーの場合はその他処理追加
sub log_output{
	my ($sec2, $min2, $hour2, $mday2, $mon2, $year2, $wday2, $yday2, $isdst2) = localtime(time);  
	my $log_yyyymmdd = sprintf("%4d/%02d/%02d-%02d:%02d:%02d ", $year2 + 1900, $mon2 +1, $mday2, $hour2, $min2, $sec2);

open(log_add,">>",$log_output_folder."\\infoblox_tool_$logfile_yyyymmdd"."\.log");
	#log_outputの第２引数が0の場合は正常処理。logに記載する。
	if($_[1]==0){
		print log_add $log_yyyymmdd." 正常処理  ".$_[0];
		#print $log_yyyymmdd." 正常処理  ".$_[0];
	#log_outputの第２引数が1の場合はエラー処理。但し、後続に影響ないエラーとして、logファイルとエラーメールファイルに記載。
	}elsif($_[1]==1){
		open(error_add,">>",$log_output_folder."\\Error_mail_".$logfile_yyyymmdd."\.txt")or die("Error_mail_".$logfile_yyyymmdd."\.txtが開けません。");
		print error_add $_[0];
		close(error_add);
		print log_add $log_yyyymmdd."エラー処理 ".$_[0];
		#print $log_yyyymmdd."エラー処理 ".$_[0];
	#log_outputの第２引数が0と1以外はエラー処理。後続処理不可となるため、ファイルの世代管理とメール送信をし終了へ
	#第2引数が2の時、世代管理処理とエラーメール送信、3の時はエラーメール送信
	}else{
		open(error_add,">",$log_output_folder."\\Error_mail_".$logfile_yyyymmdd."\.txt")or die("Error_mail_".$logfile_yyyymmdd."\.txtが開けません。");
		print error_add $_[0];
		close(error_add);
		print log_add $log_yyyymmdd."エラー処理 ".$_[0];
		#print $log_yyyymmdd."エラー処理 ".$_[0];
		#ツール実行引数が1より大きいときはAssetmentNeo連携ファイルの世代管理処理を除外
		if(@ARGV == 1){
			if($ARGV[0]==5){
				&rotate_file(5);
			}elsif(($ARGV[0]>1)and($_[1]==2)){
				&rotate_file(3);
			}elsif($_[1]==2){
				&rotate_file(2);
			}
		}elsif($_[1]==2){
			&rotate_file(2);
		}
		&error_mail;

		exit();
	}
close(log_add);
}



sub error_mail{
#config read

#メールエラーテキストを読み込む
open(my $mailer_txt,$log_output_folder."\\Error_mail_".$yyyymmdd."\.txt")or die( return);
	my @mail_txt_add = map { chomp($_); $_ } <$mailer_txt>;
close($mailer_txt);

	#mailヘッダー作成

    my $subject =   Encode::encode('MIME-Header-ISO_2022_JP' , $subject_txt );
    my $header  = "From: $from\n" .
        "To: $mailto\n" .
        "Subject: $subject\n" .
        "Mime-Version: 1.0\n" .
        "Content-Type: text/plain; charset = ISO-2022-JP\n" .
        "Content-Trensfer-Encoding: 7bit\n";
    my $mail_message = $mail_txt."\n";
	for(my $i=0;$mail_txt_add[$i];$i++){
		$mail_message .=$mail_txt_add[$i]."\n";
	}
    my $message = Encode::encode( 'iso-2022-jp' , $mail_message );
	#メール送信
    my $smtp = Net::SMTP->new( $smtp_server ,Port=> $smtp_port);
    if ( !$smtp ) {
        &log_output("メールサーバーにアクセスできません\n",1);
        exit;
    }
    $smtp->mail($from);
    $smtp->to($mailto);
    $smtp->data();
    $smtp->datasend($header);
    $smtp->datasend($message);
    $smtp->dataend();
    $smtp->quit;
}

sub rotate_file{
	my $num_k = $_[0];
	#引数5で実施している場合はMACアドレス削除リストのみ処理
	if($num_k eq 5){
		#処理したファイルのリネーム
		if(-f $list_folder."\\MAC_deletelist.csv"){
			rename($list_folder."\\MAC_deletelist.csv",$list_folder."\\MAC_deletelist_".$yyyymmdd.".csv")or die(&log_output("MAC_deletelist.csv のリネームに失敗しました。\n",3));
		}
		if(-f $list_folder."\\INetSec_deletelist.csv"){
			rename($list_folder."\\INetSec_deletelist.csv",$list_folder."\\INetSec_deletelist_".$yyyymmdd.".csv")or die(&log_output("INetSec_deletelist.csv のリネームに失敗しました。\n",3));
		}
		return;
	}
	
	#引数6で実施している場合は静的IPアドレス削除リストのみ処理
	if($num_k eq 6){
		#処理したファイルのリネーム
		if(-f $list_folder."\\DHCP_deletelist.csv"){
			rename($list_folder."\\DHCP_deletelist.csv",$list_folder."\\DHCP_deletelist_".$yyyymmdd.".csv") or die(&log_output("DHCP_deletelist.csv のリネームに失敗しました。\n",3));
		}
		return;
	}
	
	elsif(scalar(@ARGV) == 0 or ($ARGV[0]==1 and $num_k eq 1)){
		#検索文字列
		my $search_asseto = substr($importfile_new,0,-4)."_";
		#.csvを除く文字数
		my $asseto_num = length($search_asseto);
		opendir( import_dir ,$import_csvfolder) or die(&log_output("$import_csvfolder を開けません。\n",3));
			my @importfile = grep(/^$search_asseto/, readdir import_dir);
		closedir import_dir;
		my @importfile_sort = sort{substr($b,$asseto_num,-4) <=> substr($a,$asseto_num,-4)} @importfile;
		if(@importfile>0){
			for(my $i=0;$importfile_sort[$i];$i++){
				if(substr($importfile_sort[$i],$asseto_num,-4)>=$rotate_num){
					unlink($import_csvfolder."\\".$importfile_sort[$i]);
				}elsif(substr($importfile_sort[$i],$asseto_num,-4)<$rotate_num){
				rename($import_csvfolder."\\".$importfile_sort[$i],$import_csvfolder."\\".$search_asseto.(substr($importfile_sort[$i],$asseto_num,-4) + 1)."\.csv")or die(&log_output("$importfile_sort[$i] のリネームに失敗しました。\n",3));
				}
			}
		}
		rename($import_csvfolder."\\".$importfile_new,$import_csvfolder."\\".$search_asseto."1\.csv")or die(&log_output(".$importfile_new のリネームに失敗しました。\n",3));
	}elsif(scalar(@ARGV) == 0 or ( $ARGV[0]==1 and $num_k eq 2)){
		if(-f $import_csvfolder."\\".$importfile_new){
			rename($import_csvfolder."\\".$importfile_new,$import_csvfolder."\\".substr($importfile_new,0,-4)."-".$yyyymmdd."\.csv")or die(&log_output("$importfile_new のリネームに失敗しました。\n",3));
		}
		return;
	}

	#MAC登録csvと静的IPアドレスcsv
	opendir(infoblox_dir,$mac_folder) or die(&log_output("$mac_folder を開けません。\n",3));
		my @mac_rotate = grep(/^MAC_address_/, readdir infoblox_dir);
	closedir infoblox_dir;
	opendir(infoblox_dir,$mac_folder) or die(&log_output("$mac_folder を開けません。\n",3));
		my @dhcp_rotate = grep(/^DHCP_register_/, readdir infoblox_dir);
	closedir infoblox_dir;

	#名前降順にソート
	my @mac_rotate_sort = sort{$b cmp $a} @mac_rotate;
	my @dhcp_rotate_sort = sort{$b cmp $a} @dhcp_rotate;
	#$rotate_num以上の個数は削除（MAC)
	for(my $i=0;$mac_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($mac_folder."\\".$mac_rotate_sort[$i])or die(&log_output("$mac_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
	#$rotate_num以上の個数は削除（DHCP)
	for(my $i=0;$dhcp_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($mac_folder."\\".$dhcp_rotate_sort[$i])or die(&log_output("$mac_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
	#INetSec連携ファイル
	opendir(inet_dir,$export_csvfolder) or die(&log_output("$export_csvfolder を開けません。\n",3));
		my @inet_add_rotate = grep(/^INetSec_MAC_add_/, readdir inet_dir);
	closedir inet_dir;
	opendir(inet_dir,$export_csvfolder) or die(&log_output("$export_csvfolder を開けません。\n",3));
		my @inet_del_rotate = grep(/^INetSec_MAC_del_/, readdir inet_dir);
	closedir inet_dir;
	#名前降順にソート
	my @inet_add_rotate_sort = sort{$b cmp $a} @inet_add_rotate;
	my @inet_del_rotate_sort = sort{$b cmp $a} @inet_del_rotate;
	#$rotate_num以上の個数は削除（add)
	for(my $i=0;$inet_add_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($export_csvfolder."\\".$inet_add_rotate_sort[$i])or die(&log_output("$inet_add_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
	#$rotate_num以上の個数は削除（del)
	for(my $i=0;$inet_del_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($export_csvfolder."\\".$inet_del_rotate_sort[$i])or die(&log_output("$inet_add_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
	#logとエラーメール
	opendir(log_dir,$log_output_folder) or die(&log_output("$log_output_folder を開けません。\n",3));
		my @log_rotate = grep(/^infoblox_tool/, readdir log_dir);
	closedir log_dir;
	opendir(mail_dir,$log_output_folder) or die(&log_output("log_output_folder を開けません。\n",3));
		my @mail_rotate = grep(/^Error_mail/, readdir mail_dir);
	closedir mail_dir;

	#名前降順にソート
	my @log_rotate_sort = sort{$b cmp $a} @log_rotate;
	my @mail_rotate_sort = sort{$b cmp $a} @mail_rotate;
	#$rotate_num以上の個数は削除（log)
	for(my $i=0;$log_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($log_output_folder."\\".$log_rotate_sort[$i])or die(&log_output("$log_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
	#$rotate_num以上の個数は削除（del)
	for(my $i=0;$mail_rotate_sort[$i];$i++){
	 if($i>=$rotate_num){
	 	unlink($log_output_folder."\\".$mail_rotate_sort[$i])or die(&log_output("$log_rotate_sort[$i] の削除に失敗しました。\n",1));
		}
	}
}

# 正しいMACアドレスか判定
# 返値: OK=1, NG=0
sub is_macaddr{
	my $mac = $_[0];

	if($mac =~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}/){
		return 1;
	}
	else{
		return 0;
	}
}

# MACアドレス重複チェック
# 返値: 重複=1, 重複なし=0
sub is_dupricate{
	my ($record, $row) = @_;
	
	# 以前のレコードに同じMACアドレスがないかチェック
	for(my $i=0; $i<$row; $i++){
		if($$record[$i][0] eq $$record[$row][0]){
			return 1;
		}
	}
	
	return 0;
}