--[[
  The MIT License
  
  Copyright (c) 2011, Attractive Chaos <attractor@live.co.uk>
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
]]--

--[[
  This is a Lua library, more exactly a collection of Lua snippets, covering
  utilities (e.g. getopt), string operations (e.g. split), statistics (e.g.
  Fisher's exact test), special functions (e.g. logarithm gamma) and matrix
  operations (e.g. Gauss-Jordan elimination). The routines are designed to be
  as independent as possible, such that one can copy-paste relevant pieces of
  code without worrying about additional library dependencies.
]]--

--[[
  Library functions and dependencies. "a>b" means "a is required by b"; "b<a"
  means "b depends on a".

  os.getopt()
  string:split()
  io.xopen()
  table.ksmall()
  table.shuffle()
  table.pearson()
  math.lgamma() >math.lbinom() >math.igamma()
  math.igamma() <math.lgamma() >matrix.chi2()
  math.erfc()
  math.lbinom() <math.lgamma() >math.fisher_exact()
  math.bernstein_poly() <math.lbinom()
  math.fisher_exact() <math.lbinom()
  math.jackknife()
  math.fmin()
  matrix
  matrix.add()
  matrix.T() >matrix.mul()
  matrix.mul() <matrix.T()
  matrix.tostring()
  matrix.chi2() <math.igamma()
  matrix.solve()
]]--

-- Description: getopt() translated from the BSD getopt(); compatible with the default Unix getopt()
--[[ Example:
	for opt, optarg in os.getopt(arg, 'a:b') do
		if opt == 'a' then print(opt .. '=' .. optarg)
		elseif opt == 'b' then print(opt) end -- optarg is nil
	end
]]--
function os.getopt(args, ostr)
	local arg, place = nil, 0;
	return function ()
		if place == 0 then -- update scanning pointer
			if #args == 0 or args[1]:sub(1, 1) ~= '-' then return nil end
			if #args[1] >= 2 then
				if args[1]:sub(2, 2) == '-' then -- found "--"
					table.remove(args, 1);
					return nil;
				end
			end
			place = 2
		end
		local optopt = args[1]:sub(place, place);
		place = place + 1;
		local oli = ostr:find(optopt);
		if optopt == ':' or oli == nil then -- unknown option
			if optopt == '-' then return nil end
			if place > #args[1] then
				table.remove(args, 1);
				place = 0;
			end
			return '?';
		end
		oli = oli + 1;
		if ostr:sub(oli, oli) ~= ':' then -- do not need argument
			arg = nil;
			if place > #args[1] then
				table.remove(args, 1);
				place = 0;
			end
		else -- need an argument
			if place <= #args[1] then  -- no white space
				arg = args[1]:sub(place);
			else
				table.remove(args, 1);
				if #args == 0 then -- an option requiring argument is the last one
					place = 0;
					if ostr:sub(1, 1) == ':' then return ':' end
					return '?';
				else arg = args[1] end
			end
			table.remove(args, 1);
			place = 0;
		end
		return optopt, arg;
	end
end

-- Description: string split
function string:split(sep, n)
	local a, start = {}, 1;
	sep = sep or "%s+";
	repeat
		local b, e = self:find(sep, start);
		if b == nil then
			table.insert(a, self:sub(start));
			break
		end
		a[#a+1] = self:sub(start, b - 1);
		start = e + 1;
		if n and #a == n then
			table.insert(a, self:sub(start));
			break
		end
	until start > #self;
	return a;
end

-- Description: smart file open
function io.xopen(fn, mode)
	mode = mode or 'r';
	if fn == nil then return io.stdin;
	elseif fn == '-' then return (mode == 'r' and io.stdin) or io.stdout;
	elseif fn:sub(-3) == '.gz' then return (mode == 'r' and io.popen('gzip -dc ' .. fn, 'r')) or io.popen('gzip > ' .. fn, 'w');
	elseif fn:sub(-4) == '.bz2' then return (mode == 'r' and io.popen('bzip2 -dc ' .. fn, 'r')) or io.popen('bgzip2 > ' .. fn, 'w');
	else return io.open(fn, mode) end
end

-- Description: find the k-th smallest element in an array (Ref. http://ndevilla.free.fr/median/)
function table.ksmall(arr, k)
	local low, high = 1, #arr;
	while true do
		if high <= low then return arr[k] end
		if high == low + 1 then
			if arr[high] < arr[low] then arr[high], arr[low] = arr[low], arr[high] end;
			return arr[k];
		end
		local mid = math.floor((high + low) / 2);
		if arr[high] < arr[mid] then arr[mid], arr[high] = arr[high], arr[mid] end
		if arr[high] < arr[low] then arr[low], arr[high] = arr[high], arr[low] end
		if arr[low]  < arr[mid] then arr[low], arr[mid]  = arr[mid],  arr[low] end
		arr[mid], arr[low+1] = arr[low+1], arr[mid];
		local ll, hh = low + 1, high;
		while true do
			repeat ll = ll + 1 until arr[ll] >= arr[low]
			repeat hh = hh - 1 until arr[low] >= arr[hh]
			if hh < ll then break end
			arr[ll], arr[hh] = arr[hh], arr[ll];
		end
		arr[low], arr[hh] = arr[hh], arr[low];
		if hh <= k then low = ll end
		if hh >= k then high = hh - 1 end
	end
end

-- Description: shuffle/permutate an array
function table.shuffle(a)
	for i = #a, 1, -1 do
		local j = math.random(i)
		a[j], a[i] = a[i], a[j]
	end
end

-- Description: Pearson correlation coefficient
function table.pearson(a)
	local x1, y1 = 0, 0
	for _, v in pairs(a) do
		x1, y1 = x1 + v[1], y1 + v[2]
	end
	x1, y1 = x1 / #a, y1 / #a
	local x2, y2, xy = 0, 0, 0
	for _, v in pairs(a) do
		local tx, ty = v[1] - x1, v[2] - y1
		xy, x2, y2 = xy + tx * ty, x2 + tx * tx, y2 + ty * ty
	end
	return xy / math.sqrt(x2) / math.sqrt(y2)
end

--
-- Mathematics
--

-- Description: log gamma function
-- Required by: math.lbinom()
-- Reference: AS245, 2nd algorithm, http://lib.stat.cmu.edu/apstat/245
function math.lgamma(z)
	local x;
	x = 0.1659470187408462e-06     / (z+7);
	x = x + 0.9934937113930748e-05 / (z+6);
	x = x - 0.1385710331296526     / (z+5);
	x = x + 12.50734324009056      / (z+4);
	x = x - 176.6150291498386      / (z+3);
	x = x + 771.3234287757674      / (z+2);
	x = x - 1259.139216722289      / (z+1);
	x = x + 676.5203681218835      / z;
	x = x + 0.9999999999995183;
	return math.log(x) - 5.58106146679532777 - z + (z-0.5) * math.log(z+6.5);
end

-- Description: regularized incomplete gamma function
-- Dependent on: math.lgamma()
--[[
  Formulas are taken from Wiki, with additional input from Numerical
  Recipes in C (for modified Lentz's algorithm) and AS245
  (http://lib.stat.cmu.edu/apstat/245).
 
  A good online calculator is available at:
 
    http://www.danielsoper.com/statcalc/calc23.aspx
 
  It calculates upper incomplete gamma function, which equals
  math.igamma(s,z,true)*math.exp(math.lgamma(s))
]]--
function math.igamma(s, z, complement)

	local function _kf_gammap(s, z)
		local sum, x = 1, 1;
		for k = 1, 100 do
			x = x * z / (s + k);
			sum = sum + x;
			if x / sum < 1e-14 then break end
		end
		return math.exp(s * math.log(z) - z - math.lgamma(s + 1.) + math.log(sum));
	end

	local function _kf_gammaq(s, z)
		local C, D, f, TINY;
		f = 1. + z - s; C = f; D = 0.; TINY = 1e-290;
		-- Modified Lentz's algorithm for computing continued fraction. See Numerical Recipes in C, 2nd edition, section 5.2
		for j = 1, 100 do
			local d;
			local a, b = j * (s - j), j*2 + 1 + z - s;
			D = b + a * D;
			if D < TINY then D = TINY end
			C = b + a / C;
			if C < TINY then C = TINY end
			D = 1. / D;
			d = C * D;
			f = f * d;
			if math.abs(d - 1) < 1e-14 then break end
		end
		return math.exp(s * math.log(z) - z - math.lgamma(s) - math.log(f));
	end

	if complement then
		return ((z <= 1 or z < s) and 1 - _kf_gammap(s, z)) or _kf_gammaq(s, z);
	else 
		return ((z <= 1 or z < s) and _kf_gammap(s, z)) or (1 - _kf_gammaq(s, z));
	end
end

math.M_SQRT2   = 1.41421356237309504880  -- sqrt(2)
math.M_SQRT1_2 = 0.70710678118654752440  -- 1/sqrt(2)

-- Description: complement error function erfc(x): \Phi(x) = 0.5 * erfc(-x/M_SQRT2)
function math.erfc(x)
	local z = math.abs(x) * math.M_SQRT2
	if z > 37 then return (x > 0 and 0) or 2 end
	local expntl = math.exp(-0.5 * z * z)
	local p
	if z < 10. / math.M_SQRT2 then -- for small z
	    p = expntl * ((((((.03526249659989109 * z + .7003830644436881) * z + 6.37396220353165) * z + 33.912866078383) * z + 112.0792914978709) * z + 221.2135961699311) * z + 220.2068679123761)
			/ (((((((.08838834764831844 * z + 1.755667163182642) * z + 16.06417757920695) * z + 86.78073220294608) * z + 296.5642487796737) * z + 637.3336333788311) * z + 793.8265125199484) * z + 440.4137358247522);
	else p = expntl / 2.506628274631001 / (z + 1. / (z + 2. / (z + 3. / (z + 4. / (z + .65))))) end
	return (x > 0 and 2 * p) or 2 * (1 - p)
end

-- Description: log binomial coefficient
-- Dependent on: math.lgamma()
-- Required by: math.fisher_exact()
function math.lbinom(n, m)
	if m == nil then
		local a = {};
		a[0], a[n] = 0, 0;
		local t = math.lgamma(n+1);
		for m = 1, n-1 do a[m] = t - math.lgamma(m+1) - math.lgamma(n-m+1) end
		return a;
	else return math.lgamma(n+1) - math.lgamma(m+1) - math.lgamma(n-m+1) end
end

-- Description: Berstein polynomials (mainly for Bezier curves)
-- Dependent on: math.lbinom()
-- Note: to compute derivative: let beta_new[i]=beta[i+1]-beta[i]
function math.bernstein_poly(beta)
	local n = #beta - 1;
	local lbc = math.lbinom(n); -- log binomial coefficients
	return function (t)
		assert(t >= 0 and t <= 1);
		if t == 0 then return beta[1] end
		if t == 1 then return beta[n+1] end
		local sum, logt, logt1 = 0, math.log(t), math.log(1-t);
		for i = 0, n do sum = sum + beta[i+1] * math.exp(lbc[i] + i * logt + (n-i) * logt1) end
		return sum;
	end
end

-- Description: Fisher's exact test
-- Dependent on: math.lbinom()
-- Return: left-, right- and two-tail P-values
--[[
  Fisher's exact test for 2x2 congintency tables:

    n11  n12  | n1_
    n21  n22  | n2_
   -----------+----
    n_1  n_2  | n

  Reference: http://www.langsrud.com/fisher.htm
]]--
function math.fisher_exact(n11, n12, n21, n22)
	local aux; -- keep the states of n* for acceleration

	-- Description: hypergeometric function
	local function hypergeo(n11, n1_, n_1, n)
		return math.exp(math.lbinom(n1_, n11) + math.lbinom(n-n1_, n_1-n11) - math.lbinom(n, n_1));
	end

	-- Description: incremental hypergeometric function
	-- Note: aux = {n11, n1_, n_1, n, p}
	local function hypergeo_inc(n11, n1_, n_1, n)
		if n1_ ~= 0 or n_1 ~= 0 or n ~= 0 then
			aux = {n11, n1_, n_1, n, 1};
		else -- then only n11 is changed
			local mod;
			_, mod = math.modf(n11 / 11);
			if mod ~= 0 and n11 + aux[4] - aux[2] - aux[3] ~= 0 then
				if n11 == aux[1] + 1 then -- increase by 1
					aux[5] = aux[5] * (aux[2] - aux[1]) / n11 * (aux[3] - aux[1]) / (n11 + aux[4] - aux[2] - aux[3]);
					aux[1] = n11;
					return aux[5];
				end
				if n11 == aux[1] - 1 then -- descrease by 1
					aux[5] = aux[5] * aux[1] / (aux[2] - n11) * (aux[1] + aux[4] - aux[2] - aux[3]) / (aux[3] - n11);
					aux[1] = n11;
					return aux[5];
				end
			end
			aux[1] = n11;
		end
		aux[5] = hypergeo(aux[1], aux[2], aux[3], aux[4]);
		return aux[5];
	end
	
	-- Description: computing the P-value by Fisher's exact test
	local max, min, left, right, n1_, n_1, n, two, p, q, i, j;
	n1_, n_1, n = n11 + n12, n11 + n21, n11 + n12 + n21 + n22;
	max = (n_1 < n1_ and n_1) or n1_; -- max n11, for the right tail
	min = n1_ + n_1 - n;
	if min < 0 then min = 0 end -- min n11, for the left tail
	two, left, right = 1, 1, 1;
	if min == max then return 1 end -- no need to do test
	q = hypergeo_inc(n11, n1_, n_1, n); -- the probability of the current table
	-- left tail
	i, left, p = min + 1, 0, hypergeo_inc(min, 0, 0, 0);
	while p < 0.99999999 * q do
		left, p, i = left + p, hypergeo_inc(i, 0, 0, 0), i + 1;
	end
	i = i - 1;
	if p < 1.00000001 * q then left = left + p;
	else i = i - 1 end
	-- right tail
	j, right, p = max - 1, 0, hypergeo_inc(max, 0, 0, 0);
	while p < 0.99999999 * q do
		right, p, j = right + p, hypergeo_inc(j, 0, 0, 0), j - 1;
	end
	j = j + 1;
	if p < 1.00000001 * q then right = right + p;
	else j = j + 1 end
	-- two-tail
	two = left + right;
	if two > 1 then two = 1 end
	-- adjust left and right
	if math.abs(i - n11) < math.abs(j - n11) then right = 1 - left + q;
	else left = 1 - right + q end
	return left, right, two;
end

-- Description: Delete-m Jackknife
--[[
  Given g groups of values with a statistics estimated from m[i] samples in
  i-th group being t[i], compute the mean and the variance. t0 below is the
  estimate from all samples. Reference:

     Busing et al. (1999) Delete-m Jackknife for unequal m. Statistics and Computing, 9:3-8.
]]--
function math.jackknife(g, m, t, t0)
	local h, n, sum = {}, 0, 0;
	for j = 1, g do n = n + m[j] end
	if t0 == nil then -- When t0 is absent, estimate it in a naive way
		t0 = 0;
		for j = 1, g do t0 = t0 + m[j] * t[j] end
		t0 = t0 / n;
	end
	local mean, var = 0, 0;
	for j = 1, g do
		h[j] = n / m[j];
		mean = mean + (1 - m[j] / n) * t[j];
	end
	mean = g * t0 - mean; -- Eq. (8)
	for j = 1, g do
		local x = h[j] * t0 - (h[j] - 1) * t[j] - mean;
		var = var + 1 / (h[j] - 1) * x * x;
	end
	var = var / g;
	return mean, var;
end

-- Description: Hooke-Jeeves derivative-free optimization
function math.fmin(func, x, data, r, eps, max_calls)
	local n, n_calls = #x, 0;
	r = r or 0.5;
	eps = eps or 1e-7;
	max_calls = max_calls or 50000

	function fmin_aux(x1, data, fx1, dx) -- auxiliary function
		local ftmp;
		for k = 1, n do
			x1[k] = x1[k] + dx[k];
			local ftmp = func(x1, data); n_calls = n_calls + 1;
			if ftmp < fx1 then fx1 = ftmp;
			else -- search the opposite direction
				dx[k] = -dx[k];
				x1[k] = x1[k] + dx[k] + dx[k];
				ftmp = func(x1, data); n_calls = n_calls + 1;
				if ftmp < fx1 then fx1 = ftmp
				else x1[k] = x1[k] - dx[k] end -- back to the original x[k]
			end
		end
		return fx1; -- here: fx1=f(n,x1)
	end

	local dx, x1 = {}, {};
	for k = 1, n do -- initial directions, based on MGJ
		dx[k] = math.abs(x[k]) * r;
		if dx[k] == 0 then dx[k] = r end;
	end
	local radius = r;
	local fx1, fx;
	fx = func(x, data); fx1 = fx; n_calls = n_calls + 1;
	while true do
		for i = 1, n do x1[i] = x[i] end; -- x1 = x
		fx1 = fmin_aux(x1, data, fx, dx);
		while fx1 < fx do
			for k = 1, n do
				local t = x[k];
				dx[k] = (x1[k] > x[k] and math.abs(dx[k])) or -math.abs(dx[k]);
				x[k] = x1[k];
				x1[k] = x1[k] + x1[k] - t;
			end
			fx = fx1;
			if n_calls >= max_calls then break end
			fx1 = func(x1, data); n_calls = n_calls + 1;
			fx1 = fmin_aux(x1, data, fx1, dx);
			if fx1 >= fx then break end
			local kk = n;
			for k = 1, n do
				if math.abs(x1[k] - x[k]) > .5 * math.abs(dx[k]) then
					kk = k;
					break;
				end
			end
			if kk == n then break end
		end
		if radius >= eps then
			if n_calls >= max_calls then break end
			radius = radius * r;
			for k = 1, n do dx[k] = dx[k] * r end
		else break end
	end
	return fx1, n_calls;
end

--
-- Matrix
--

matrix = {}

-- Description: matrix transpose
-- Required by: matrix.mul()
function matrix.T(a)
	local m, n, x = #a, #a[1], {};
	for i = 1, n do
		x[i] = {};
		for j = 1, m do x[i][j] = a[j][i] end
	end
	return x;
end

-- Description: matrix add
function matrix.add(a, b)
	assert(#a == #b and #a[1] == #b[1]);
	local m, n, x = #a, #a[1], {};
	for i = 1, m do
		x[i] = {};
		local ai, bi, xi = a[i], b[i], x[i];
		for j = 1, n do xi[j] = ai[j] + bi[j] end
	end
	return x;
end

-- Description: matrix mul
-- Dependent on: matrix.T()
-- Note: much slower without transpose
function matrix.mul(a, b)
	assert(#a[1] == #b);
	local m, n, p, x = #a, #a[1], #b[1], {};
	local c = matrix.T(b); -- transpose for efficiency
	for i = 1, m do
		x[i] = {}
		local xi = x[i];
		for j = 1, p do
			local sum, ai, cj = 0, a[i], c[j];
			for k = 1, n do sum = sum + ai[k] * cj[k] end
			xi[j] = sum;
		end
	end
	return x;
end

-- Description: matrix print
function matrix.tostring(a)
	local z = {};
	for i = 1, #a do
		z[i] = table.concat(a[i], "\t");
	end
	return table.concat(z, "\n");
end

-- Description: chi^2 test for contingency tables
-- Dependent on: math.igamma()
function matrix.chi2(a)
	if #a == 2 and #a[1] == 2 then -- 2x2 table
		local x, z
		x = (a[1][1] + a[1][2]) * (a[2][1] + a[2][2]) * (a[1][1] + a[2][1]) * (a[1][2] + a[2][2])
		if x == 0 then return 0, 1, false end
		z = a[1][1] * a[2][2] - a[1][2] * a[2][1]
		z = (a[1][1] + a[1][2] + a[2][1] + a[2][2]) * z * z / x
		return z, math.igamma(.5, .5 * z, true), true
	else -- generic table
		local rs, cs, n, m, N, z = {}, {}, #a, #a[1], 0, 0
		for i = 1, n do rs[i] = 0 end
		for j = 1, m do cs[j] = 0 end
		for i = 1, n do -- compute column sum and row sum
			for j = 1, m do cs[j], rs[i] = cs[j] + a[i][j], rs[i] + a[i][j] end
		end
		for i = 1, n do N = N + rs[i] end
		for i = 1, n do -- compute the chi^2 statistics
			for j = 1, m do
				local E = rs[i] * cs[j] / N;
				z = z + (a[i][j] - E) * (a[i][j] - E) / E
			end
		end
		return z, math.igamma(.5 * (n-1) * (m-1), .5 * z, true), true;
	end
end

-- Description: Gauss-Jordan elimination (solving equations; computing inverse)
-- Note: on return, a[n][n] is the inverse; b[n][m] is the solution
-- Reference: Section 2.1, Numerical Recipes in C, 2nd edition
function matrix.solve(a, b)
	assert(#a == #a[1]);
	local n, m = #a, (b and #b[1]) or 0;
	local xc, xr, ipiv = {}, {}, {};
	local ic, ir;

	for j = 1, n do ipiv[j] = 0 end
	for i = 1, n do
		local big = 0;
		for j = 1, n do
			local aj = a[j];
			if ipiv[j] ~= 1 then
				for k = 1, n do
					if ipiv[k] == 0 then
						if math.abs(aj[k]) >= big then
							big = math.abs(aj[k]);
							ir, ic = j, k;
						end
					elseif ipiv[k] > 1 then return -2 end -- singular matrix
				end
			end
		end
		ipiv[ic] = ipiv[ic] + 1;
		if ir ~= ic then
			for l = 1, n do a[ir][l], a[ic][l] = a[ic][l], a[ir][l] end
			if b then
				for l = 1, m do b[ir][l], b[ic][l] = b[ic][l], b[ir][l] end
			end
		end
		xr[i], xc[i] = ir, ic;
		if a[ic][ic] == 0 then return -3 end -- singular matrix
		local pivinv = 1 / a[ic][ic];
		a[ic][ic] = 1;
		for l = 1, n do a[ic][l] = a[ic][l] * pivinv end
		if b then
			for l = 1, n do b[ic][l] = b[ic][l] * pivinv end
		end
		for ll = 1, n do
			if ll ~= ic then
				local tmp = a[ll][ic];
				a[ll][ic] = 0;
				local all, aic = a[ll], a[ic];
				for l = 1, n do all[l] = all[l] - aic[l] * tmp end
				if b then
					local bll, bic = b[ll], b[ic];
					for l = 1, m do bll[l] = bll[l] - bic[l] * tmp end
				end
			end
		end
	end
	for l = n, 1, -1 do
		if xr[l] ~= xc[l] then
			for k = 1, n do a[k][xr[l]], a[k][xc[l]] = a[k][xc[l]], a[k][xr[l]] end
		end
	end
	return 0;
end
