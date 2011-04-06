-- bioinformatics routines

-- Description: read a fasta/fastq file
local function readseq(fp)
	local finished, last = false, nil;
	return function()
		local match;
		if finished then return nil end
		if (last == nil) then -- the first record or a record following a fastq
			for l in fp:lines() do
				if l:byte(1) == 62 or l:byte(1) == 64 then -- ">" || "@"
					last = l;
					break;
				end
			end
			if last == nil then
				finished = true;
				return nil;
			end
		end
		local tmp = last:find("%s");
		name = (tmp and last:sub(2, tmp-1)) or last:sub(2); -- sequence name
		local seqs = {};
		local c; -- the first character of the last line
		last = nil;
		for l in fp:lines() do -- read sequence
			c = l:byte(1);
			if c == 62 or c == 64 or c == 43 then
				last = l;
				break;
			end
			table.insert(seqs, l);
		end
		if last == nil then finished = true end -- end of file
		if c ~= 43 then return name, table.concat(seqs) end -- a fasta record
		local seq, len = table.concat(seqs), 0; -- prepare to parse quality
		seqs = {};
		for l in fp:lines() do -- read quality
			table.insert(seqs, l);
			len = len + #l;
			if len >= #seq then
				last = nil;
				return name, seq, table.concat(seqs);
			end
		end
		finished = true;
		return name, seq;
	end
end

-- extract subsequence from a fasta file indexe by samtools faidx
local function faidxsub(fn)
	local fpidx = io.open(fn .. ".fai");
	if fpidx == nil then
		io.stderr:write("[faidxsub] fail to open the FASTA index file.\n");
		return nil
	end
	local idx = {};
	for l in fpidx:lines() do
		local name, len, offset, line_blen, line_len = l:match("(%S+)%s(%d+)%s(%d+)%s(%d+)%s(%d+)");
		if name then
			idx[name] = {tonumber(len), offset, line_blen, line_len};
		end
	end
	fpidx:close();
	local fp = io.open(fn);
	return function(name, beg_, end_) -- 0-based coordinate
		if name == nil then fp:close(); return nil; end
		if idx[name] then
			local a = idx[name];
			beg_ = beg_ or 0;
			end_ = end_ or a[1];
			end_ = (end_ <= a[1] and end_) or a[1];
			local fb, fe = math.floor(beg_ / a[3]), math.floor(end_ / a[3]);
			local qb, qe = beg_ - fb * a[3], end_ - fe * a[3];
			fp:seek("set", a[2] + fb * a[4] + qb);
			local s = fp:read((fe - fb) * a[4] + (qe - qb)):gsub("%s", "");
			return s;
		end
	end
end

bio = {
	readseq = readseq,
	faidxsub = faidxsub
}

bio.nt16 = {
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15, 1,14, 2, 13,15,15, 4, 11,15,15,12, 15, 3,15,15, 15,15, 5, 6,  8,15, 7, 9,  0,10,15,15, 15,15,15,15,
	15, 1,14, 2, 13,15,15, 4, 11,15,15,12, 15, 3,15,15, 15,15, 5, 6,  8,15, 7, 9,  0,10,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15
}
bio.ntcnt = { 4, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 }
