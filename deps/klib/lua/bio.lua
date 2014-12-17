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

--Description: Index a list of intervals and test if a given interval overlaps with the list
--Example: lua -lbio -e 'a={{100,201},{200,300},{400,600}};f=bio.intvovlp(a);print(f(600,700))'
--[[
  By default, we keep for each tiling 8192 window the interval overlaping the
  window while having the smallest start position. This method may not work
  well when most intervals are small but few intervals span a long distance.
]]--
local function intvovlp(intv, bits)
	bits = bits or 13 -- the default bin size is 8192 = 1<<13
	table.sort(intv, function(a,b) return a[1] < b[1] end) -- sort by the start
	-- merge intervals; the step speeds up testing, but can be skipped
	local b, e, k = -1, -1, 1
	for i = 1, #intv do
		if e < intv[i][1] then
			if e >= 0 then intv[k], k = {b, e}, k + 1 end
			b, e = intv[i][1], intv[i][2]
		else e = intv[i][2] end
	end
	if e >= 0 then intv[k] = {b, e} end
	while #a > k do table.remove(a) end -- truncate the interval list
	-- build the index for the list of intervals
	local idx, size, max = {}, math.pow(2, bits), 0
	for i = 1, #a do
		b = math.modf(intv[i][1] / size)
		e = math.modf(intv[i][2] / size)
		if b == e then idx[b] = idx[b] or i
		else for j = b, e do idx[j] = idx[j] or i end end
		max = (max > e and max) or e
	end
	-- return a function (closure)
	return function(_beg, _end)
		local x = math.modf(_beg / size)
		if x > max then return false end
		local off = idx[x]; -- the start bin
		if off == nil then -- the following is not the best in efficiency
			for i = x - 1, 0, -1 do -- find the minimum bin with a value
				if idx[i] ~= nil then off = idx[i]; break; end
			end
			if off == nil then return false end
		end
		for i = off, #intv do -- start from off and search for overlaps
			if intv[i][1] >= _end then return false
			elseif intv[i][2] > _beg then return true end 
		end
		return false
	end
end

bio = {
	readseq = readseq,
	faidxsub = faidxsub,
	intvovlp = intvovlp
}

bio.nt16 = {
[0]=15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15, 1,14, 2, 13,15,15, 4, 11,15,15,12, 15, 3,15,15, 15,15, 5, 6,  8,15, 7, 9,  0,10,15,15, 15,15,15,15,
	15, 1,14, 2, 13,15,15, 4, 11,15,15,12, 15, 3,15,15, 15,15, 5, 6,  8,15, 7, 9,  0,10,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15,
	15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15, 15,15,15,15
}
bio.ntcnt  = { [0]=4, 1, 1,  2, 1,  2, 2,  3, 1, 2, 2,  3, 2,  3, 3,  4 }
bio.ntcomp = { [0]=0, 8, 4, 12, 2, 10, 9, 14, 1, 6, 5, 13, 3, 11, 7, 15 }
bio.ntrev  = 'XACMGRSVTWYHKDBN'
