-- Fullentrega: datos compartidos entre empresa y repartidores.
-- Las tablas tienen RLS activado y ninguna política: el navegador no puede leerlas
-- directamente. Todo pasa por funciones que validan el código de acceso.

create table if not exists public.fe_config (
  clave text primary key,
  valor text not null
);

create table if not exists public.fe_codigos (
  codigo  text primary key,
  nombre  text not null,
  tipo    text not null check (tipo in ('empresa', 'repartidor')),
  empresa text not null,           -- código de la empresa a la que pertenece
  creado  timestamptz not null default now()
);

create table if not exists public.fe_repartidores (
  id      uuid primary key default gen_random_uuid(),
  empresa text not null references public.fe_codigos(codigo) on delete cascade,
  nombre  text not null,
  tel     text,
  creado  timestamptz not null default now()
);

create table if not exists public.fe_pedidos (
  id          bigint generated always as identity primary key,
  empresa     text not null references public.fe_codigos(codigo) on delete cascade,
  cliente     text not null,
  direccion   text not null,
  descripcion text,
  telefono    text,
  repartidor  text,
  estado      text not null default 'pendiente'
              check (estado in ('pendiente', 'en-camino', 'entregado', 'cancelado')),
  creado      timestamptz not null default now(),
  actualizado timestamptz not null default now()
);

create index if not exists fe_pedidos_empresa_idx on public.fe_pedidos (empresa, creado desc);
create index if not exists fe_repartidores_empresa_idx on public.fe_repartidores (empresa);
create index if not exists fe_codigos_empresa_idx on public.fe_codigos (empresa);

alter table public.fe_config       enable row level security;
alter table public.fe_codigos      enable row level security;
alter table public.fe_repartidores enable row level security;
alter table public.fe_pedidos      enable row level security;

-- Hash SHA-256 de la contraseña de administrador (el mismo que usaba la app).
insert into public.fe_config (clave, valor)
values ('admin_hash', '89cffe6c91d69029fd32f335139e73888daf18d8b983f41ba9013c97a5dad6a6')
on conflict (clave) do nothing;

-- Cuenta demo
insert into public.fe_codigos (codigo, nombre, tipo, empresa) values
  ('EMP-DEMO', 'Demo Empresa', 'empresa', 'EMP-DEMO'),
  ('REP-DEMO', 'Demo Repartidor', 'repartidor', 'EMP-DEMO')
on conflict (codigo) do nothing;

-- ── Funciones internas ──────────────────────────────────────────────

create or replace function public.fe_sesion(p_codigo text)
returns public.fe_codigos
language sql stable security definer set search_path = public as $$
  select * from public.fe_codigos where codigo = upper(trim(p_codigo));
$$;

create or replace function public.fe_es_admin(p_pass text)
returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select valor = encode(sha256(convert_to(coalesce(p_pass, ''), 'UTF8')), 'hex')
       from public.fe_config where clave = 'admin_hash'),
    false);
$$;

-- ── Login y datos ───────────────────────────────────────────────────

create or replace function public.fe_login(p_codigo text)
returns json
language plpgsql stable security definer set search_path = public as $$
declare s public.fe_codigos;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null then return null; end if;
  return json_build_object('codigo', s.codigo, 'nombre', s.nombre, 'tipo', s.tipo, 'empresa', s.empresa);
end $$;

create or replace function public.fe_datos(p_codigo text)
returns json
language plpgsql stable security definer set search_path = public as $$
declare s public.fe_codigos;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null then raise exception 'codigo_invalido'; end if;
  return json_build_object(
    'pedidos', coalesce((
      select json_agg(json_build_object(
        'id', p.id, 'cliente', p.cliente, 'direccion', p.direccion,
        'descripcion', p.descripcion, 'telefono', p.telefono,
        'repartidor', p.repartidor, 'estado', p.estado, 'creado', p.creado
      ) order by p.creado)
      from public.fe_pedidos p where p.empresa = s.empresa), '[]'::json),
    'repartidores', coalesce((
      select json_agg(json_build_object('id', r.id, 'nombre', r.nombre, 'tel', r.tel) order by r.nombre)
      from public.fe_repartidores r where r.empresa = s.empresa), '[]'::json)
  );
end $$;

-- ── Acciones de la empresa ──────────────────────────────────────────

create or replace function public.fe_crear_pedido(
  p_codigo text, p_cliente text, p_direccion text,
  p_descripcion text, p_telefono text, p_repartidor text)
returns bigint
language plpgsql security definer set search_path = public as $$
declare s public.fe_codigos; nuevo bigint;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null or s.tipo <> 'empresa' then raise exception 'sin_permiso'; end if;
  if coalesce(trim(p_cliente), '') = '' or coalesce(trim(p_direccion), '') = '' then
    raise exception 'datos_incompletos';
  end if;
  insert into public.fe_pedidos (empresa, cliente, direccion, descripcion, telefono, repartidor)
  values (s.empresa, left(trim(p_cliente), 200), left(trim(p_direccion), 300),
          nullif(left(trim(p_descripcion), 500), ''), nullif(left(trim(p_telefono), 40), ''),
          nullif(trim(p_repartidor), ''))
  returning id into nuevo;
  return nuevo;
end $$;

create or replace function public.fe_eliminar_pedido(p_codigo text, p_id bigint)
returns void
language plpgsql security definer set search_path = public as $$
declare s public.fe_codigos;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null or s.tipo <> 'empresa' then raise exception 'sin_permiso'; end if;
  delete from public.fe_pedidos where id = p_id and empresa = s.empresa;
end $$;

create or replace function public.fe_estado_pedido(p_codigo text, p_id bigint, p_estado text)
returns void
language plpgsql security definer set search_path = public as $$
declare s public.fe_codigos;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null then raise exception 'sin_permiso'; end if;
  update public.fe_pedidos set estado = p_estado, actualizado = now()
   where id = p_id and empresa = s.empresa;
end $$;

create or replace function public.fe_agregar_repartidor(p_codigo text, p_nombre text, p_tel text)
returns uuid
language plpgsql security definer set search_path = public as $$
declare s public.fe_codigos; nuevo uuid;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null or s.tipo <> 'empresa' then raise exception 'sin_permiso'; end if;
  if coalesce(trim(p_nombre), '') = '' then raise exception 'datos_incompletos'; end if;
  insert into public.fe_repartidores (empresa, nombre, tel)
  values (s.empresa, left(trim(p_nombre), 100), nullif(left(trim(p_tel), 40), ''))
  returning id into nuevo;
  return nuevo;
end $$;

create or replace function public.fe_eliminar_repartidor(p_codigo text, p_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
declare s public.fe_codigos;
begin
  s := public.fe_sesion(p_codigo);
  if s.codigo is null or s.tipo <> 'empresa' then raise exception 'sin_permiso'; end if;
  delete from public.fe_repartidores where id = p_id and empresa = s.empresa;
end $$;

-- ── Administración de códigos ───────────────────────────────────────

create or replace function public.fe_admin_codigos(p_pass text)
returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.fe_es_admin(p_pass) then raise exception 'sin_permiso'; end if;
  return coalesce((
    select json_agg(json_build_object(
      'codigo', c.codigo, 'nombre', c.nombre, 'tipo', c.tipo, 'empresa', c.empresa,
      'empresa_nombre', e.nombre) order by c.creado desc)
    from public.fe_codigos c left join public.fe_codigos e on e.codigo = c.empresa), '[]'::json);
end $$;

create or replace function public.fe_admin_crear_codigo(
  p_pass text, p_nombre text, p_tipo text, p_codigo text, p_empresa text)
returns text
language plpgsql security definer set search_path = public as $$
declare v_codigo text; v_empresa text;
begin
  if not public.fe_es_admin(p_pass) then raise exception 'sin_permiso'; end if;
  if coalesce(trim(p_nombre), '') = '' then raise exception 'datos_incompletos'; end if;
  if p_tipo not in ('empresa', 'repartidor') then raise exception 'tipo_invalido'; end if;

  v_codigo := upper(trim(coalesce(p_codigo, '')));
  if v_codigo = '' then
    v_codigo := (case when p_tipo = 'empresa' then 'EMP-' else 'REP-' end)
                || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
  end if;
  if length(v_codigo) < 6 then raise exception 'codigo_corto'; end if;
  if exists (select 1 from public.fe_codigos where codigo = v_codigo) then
    raise exception 'codigo_existe';
  end if;

  if p_tipo = 'empresa' then
    v_empresa := v_codigo;
  else
    v_empresa := upper(trim(coalesce(p_empresa, '')));
    if not exists (select 1 from public.fe_codigos where codigo = v_empresa and tipo = 'empresa') then
      raise exception 'empresa_invalida';
    end if;
  end if;

  insert into public.fe_codigos (codigo, nombre, tipo, empresa)
  values (v_codigo, left(trim(p_nombre), 120), p_tipo, v_empresa);
  return v_codigo;
end $$;

create or replace function public.fe_admin_eliminar_codigo(p_pass text, p_codigo text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.fe_es_admin(p_pass) then raise exception 'sin_permiso'; end if;
  -- Borrar una empresa borra también sus repartidores, pedidos y códigos de repartidor.
  delete from public.fe_codigos where empresa = upper(trim(p_codigo)) and tipo = 'repartidor'
    and exists (select 1 from public.fe_codigos where codigo = upper(trim(p_codigo)) and tipo = 'empresa');
  delete from public.fe_codigos where codigo = upper(trim(p_codigo));
end $$;

-- ── Permisos: el navegador solo puede llamar estas funciones ───────

revoke all on function public.fe_sesion(text) from public, anon, authenticated;
revoke all on function public.fe_es_admin(text) from public, anon, authenticated;

grant execute on function public.fe_login(text) to anon, authenticated;
grant execute on function public.fe_datos(text) to anon, authenticated;
grant execute on function public.fe_crear_pedido(text, text, text, text, text, text) to anon, authenticated;
grant execute on function public.fe_eliminar_pedido(text, bigint) to anon, authenticated;
grant execute on function public.fe_estado_pedido(text, bigint, text) to anon, authenticated;
grant execute on function public.fe_agregar_repartidor(text, text, text) to anon, authenticated;
grant execute on function public.fe_eliminar_repartidor(text, uuid) to anon, authenticated;
grant execute on function public.fe_admin_codigos(text) to anon, authenticated;
grant execute on function public.fe_admin_crear_codigo(text, text, text, text, text) to anon, authenticated;
grant execute on function public.fe_admin_eliminar_codigo(text, text) to anon, authenticated;
